#include "httpserver.h"
#include <QSqlQuery>
#include <QSqlError>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QUrlQuery>
#include <QDebug>
#include <QDateTime>

HttpServer::HttpServer(QObject *parent) : QObject(parent), server(this)
{
    connect(&server, &QTcpServer::newConnection, this, &HttpServer::handleNewConnection);
    initializeDatabase();
}

bool HttpServer::listen(const QHostAddress &address, quint16 port)
{
    return server.listen(address, port);
}

void HttpServer::handleNewConnection()
{
    QTcpSocket *socket = server.nextPendingConnection();
    qInfo() << "New connection from:" << socket->peerAddress().toString();
    connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
        handleRequest(socket);
    });
    connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
}

void HttpServer::handleRequest(QTcpSocket *socket)
{
    QByteArray request = socket->readAll();
    QString requestStr = QString::fromUtf8(request);
    
    qInfo() << "Received request:" << requestStr.split("\r\n").first();
    // Log the full request for debugging
    qInfo() << "Full HTTP request:\n" << requestStr;
    
    // Parse HTTP request
    QStringList lines = requestStr.split("\r\n");
    if (lines.isEmpty()) return;
    
    QString firstLine = lines[0];
    QStringList parts = firstLine.split(" ");
    if (parts.size() < 2) return;
    
    QString method = parts[0];
    QString path = parts[1];
    
    qInfo() << "Request:" << method << path;
    
    // Extract body (everything after double \r\n)
    QString body;
    int bodyIndex = requestStr.indexOf("\r\n\r\n");
    if (bodyIndex != -1) {
        body = requestStr.mid(bodyIndex + 4);
    }
    
    // Route handling
    if (path == "/api/health") {
        handleHealthCheck(socket);
    } else if (path == "/api/auth/login" && method == "POST") {
        handleUserLogin(socket, body);
    } else if (path == "/api/auth/register" && method == "POST") {
        handleUserRegister(socket, body);
    } else if (path == "/api/restaurants" && method == "GET") {
        handleGetRestaurants(socket);
    } else if (path.startsWith("/api/restaurants/") && path.endsWith("/menu") && method == "GET") {
        QString restaurantId = path.split("/")[3];
        handleGetMenu(socket, restaurantId);
    } else if (path == "/api/orders" && method == "POST") {
        handleCreateOrder(socket, body);
    } else if (path.startsWith("/api/orders") && method == "GET") {
        // Extract user ID from query parameters or headers
        QString userId = "1"; // For now, hardcoded - you'll need to implement proper authentication
        handleGetOrders(socket, userId);
    } else if (path.startsWith("/api/orders/") && method == "PUT") {
        QString orderId = path.split("/")[3];
        handleUpdateOrderStatus(socket, orderId, body);
    } else if (path == "/api/menu" && method == "POST") {
        qInfo() << "[DEBUG] /api/menu POST body:" << body;
        handleAddMenuItem(socket, body);
    } else if (path.startsWith("/api/menu/") && method == "PUT") {
        QString menuItemId = path.split("/")[3];
        handleUpdateMenuItem(socket, menuItemId, body);
    } else if (path.startsWith("/api/menu/") && method == "DELETE") {
        QString menuItemId = path.split("/")[3];
        handleDeleteMenuItem(socket, menuItemId);
    } else if (path == "/api/users/set-restaurant" && method == "POST") {
        handleSetUserRestaurant(socket, body);
    } else if (path == "/api/restaurants/create" && method == "POST") {
        handleCreateRestaurant(socket, body);
    } else if (path.startsWith("/api/users/") && method == "GET") {
        // /api/users/{id}
        QStringList pathParts = path.split("/");
        if (pathParts.size() >= 4) {
            QString userId = pathParts[3];
            handleGetUserInfo(socket, userId);
        } else {
            sendJsonResponse(socket, 400, QJsonObject{{"error", "Missing user id"}});
        }
    } else {
        sendResponse(socket, 404, "text/plain", "404 Not Found");
    }
}

void HttpServer::sendResponse(QTcpSocket *socket, int statusCode, const QString &contentType, const QByteArray &body)
{
    QString statusText;
    switch (statusCode) {
        case 200: statusText = "OK"; break;
        case 201: statusText = "Created"; break;
        case 400: statusText = "Bad Request"; break;
        case 401: statusText = "Unauthorized"; break;
        case 404: statusText = "Not Found"; break;
        case 500: statusText = "Internal Server Error"; break;
        default: statusText = "Unknown"; break;
    }
    
    QString response = QString("HTTP/1.1 %1 %2\r\n"
                              "Content-Type: %3\r\n"
                              "Content-Length: %4\r\n"
                              "Access-Control-Allow-Origin: *\r\n"
                              "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
                              "Access-Control-Allow-Headers: Content-Type\r\n"
                              "\r\n")
                              .arg(statusCode)
                              .arg(statusText)
                              .arg(contentType)
                              .arg(body.size());
    
    socket->write(response.toUtf8() + body);
    socket->flush();
    socket->close();
}

void HttpServer::sendJsonResponse(QTcpSocket *socket, int statusCode, const QJsonObject &json)
{
    QJsonDocument doc(json);
    sendResponse(socket, statusCode, "application/json", doc.toJson());
}

void HttpServer::sendJsonResponse(QTcpSocket *socket, int statusCode, const QJsonArray &json)
{
    QJsonDocument doc(json);
    sendResponse(socket, statusCode, "application/json", doc.toJson());
}

void HttpServer::handleHealthCheck(QTcpSocket *socket)
{
    QJsonObject response;
    response["status"] = "Server is running";
    response["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    sendJsonResponse(socket, 200, response);
}

void HttpServer::handleUserLogin(QTcpSocket *socket, const QString &body)
{
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    
    if (error.error != QJsonParseError::NoError) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Invalid JSON";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    QJsonObject request = doc.object();
    QString username = request["username"].toString();
    QString password = request["password"].toString();
    
    if (username.isEmpty() || password.isEmpty()) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Username and password are required";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    QJsonObject userInfo = authenticateUser(username, password);
    if (userInfo.contains("error")) {
        sendJsonResponse(socket, 401, userInfo);
    } else {
        sendJsonResponse(socket, 200, userInfo);
    }
}

void HttpServer::handleUserRegister(QTcpSocket *socket, const QString &body)
{
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    
    if (error.error != QJsonParseError::NoError) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Invalid JSON";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    QJsonObject request = doc.object();
    QString username = request["username"].toString();
    QString password = request["password"].toString();
    QString userType = request["userType"].toString();
    
    if (username.isEmpty() || password.isEmpty() || userType.isEmpty()) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Username, password, and userType are required";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    QSqlQuery query;
    if (userType == "restaurant") {
        // Insert user first
        query.prepare("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)");
        query.addBindValue(username);
        query.addBindValue(password);
        query.addBindValue(userType);
        if (!query.exec()) {
            sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to register user"}});
            return;
        }
        int userId = query.lastInsertId().toInt();
        // Insert restaurant with id = userId
        QSqlQuery restQuery;
        restQuery.prepare("INSERT INTO restaurants (id, name, type, location, description, min_price, max_price) VALUES (?, ?, ?, ?, ?, ?, ?)");
        restQuery.addBindValue(userId);
        restQuery.addBindValue("New Restaurant");
        restQuery.addBindValue("Unknown");
        restQuery.addBindValue("Unknown");
        restQuery.addBindValue("");
        restQuery.addBindValue(0);
        restQuery.addBindValue(0);
        if (!restQuery.exec()) {
            // Rollback user if restaurant insert fails
            QSqlQuery delUser;
            delUser.prepare("DELETE FROM users WHERE id = ?");
            delUser.addBindValue(userId);
            delUser.exec();
            sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to create restaurant"}});
            return;
        }
        // Update user's restaurant_id
        QSqlQuery updateUser;
        updateUser.prepare("UPDATE users SET restaurant_id = ? WHERE id = ?");
        updateUser.addBindValue(userId);
        updateUser.addBindValue(userId);
        if (!updateUser.exec()) {
            sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to update user restaurant_id"}});
            return;
        }
        sendJsonResponse(socket, 200, QJsonObject{{"message", "User registered successfully"}});
    } else {
        query.prepare("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)");
        query.addBindValue(username);
        query.addBindValue(password);
        query.addBindValue(userType);
        if (!query.exec()) {
            sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to register user"}});
            return;
        }
        sendJsonResponse(socket, 201, QJsonObject{{"message", "User registered successfully"}});
    }
}

void HttpServer::handleGetRestaurants(QTcpSocket *socket)
{
    QJsonArray restaurants = getRestaurantsList();
    sendJsonResponse(socket, 200, restaurants);
}

void HttpServer::handleGetMenu(QTcpSocket *socket, const QString &restaurantId)
{
    QJsonArray menu = getMenuItems(restaurantId);
    sendJsonResponse(socket, 200, menu);
}

void HttpServer::handleCreateOrder(QTcpSocket *socket, const QString &body)
{
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    
    if (error.error != QJsonParseError::NoError) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Invalid JSON";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    QJsonObject request = doc.object();
    QString customerId = request["customerId"].toString();
    QString restaurantId = request["restaurantId"].toString();
    QJsonArray items = request["items"].toArray();
    int totalAmount = request["totalAmount"].toInt();
    
    if (customerId.isEmpty() || restaurantId.isEmpty() || items.isEmpty()) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Missing required order information";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    if (createOrder(customerId, restaurantId, items, totalAmount)) {
        QJsonObject response;
        response["message"] = "Order created successfully";
        sendJsonResponse(socket, 201, response);
    } else {
        QJsonObject errorResponse;
        errorResponse["error"] = "Failed to create order";
        sendJsonResponse(socket, 500, errorResponse);
    }
}

void HttpServer::handleGetOrders(QTcpSocket *socket, const QString &userId)
{
    QJsonArray orders = getOrders(userId, "customer"); // You'll need to determine user type
    sendJsonResponse(socket, 200, orders);
}

void HttpServer::handleUpdateOrderStatus(QTcpSocket *socket, const QString &orderId, const QString &body)
{
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    
    if (error.error != QJsonParseError::NoError) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Invalid JSON";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    QJsonObject request = doc.object();
    QString status = request["status"].toString();
    
    if (status.isEmpty()) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Status is required";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    if (updateOrderStatus(orderId, status)) {
        QJsonObject response;
        response["message"] = "Order status updated successfully";
        sendJsonResponse(socket, 200, response);
    } else {
        QJsonObject errorResponse;
        errorResponse["error"] = "Failed to update order status";
        sendJsonResponse(socket, 500, errorResponse);
    }
}

void HttpServer::handleAddMenuItem(QTcpSocket *socket, const QString &body)
{
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    
    if (error.error != QJsonParseError::NoError) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Invalid JSON";
        sendJsonResponse(socket, 400, errorResponse);
        qWarning() << "[DEBUG] Invalid JSON received in /api/menu POST:" << body;
        return;
    }
    
    QJsonObject request = doc.object();
    QString restaurantId = request["restaurantId"].toString();
    QString foodType = request["foodType"].toString();
    QString foodName = request["foodName"].toString();
    QString foodDetails = request["foodDetails"].toString();
    int price = request["price"].toInt();
    qInfo() << "[DEBUG] Parsed fields:";
    qInfo() << "  restaurantId:" << restaurantId;
    qInfo() << "  foodType:" << foodType;
    qInfo() << "  foodName:" << foodName;
    qInfo() << "  foodDetails:" << foodDetails;
    qInfo() << "  price:" << price;
    
    if (restaurantId.isEmpty() || foodType.isEmpty() || foodName.isEmpty() || foodDetails.isEmpty() || price <= 0) {
        QJsonObject errorResponse;
        errorResponse["error"] = "All fields are required and price must be positive";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    if (addMenuItem(restaurantId, foodType, foodName, foodDetails, price)) {
        QJsonObject response;
        response["message"] = "Menu item added successfully";
        sendJsonResponse(socket, 201, response);
    } else {
        QJsonObject errorResponse;
        errorResponse["error"] = "Failed to add menu item";
        sendJsonResponse(socket, 500, errorResponse);
    }
}

void HttpServer::handleUpdateMenuItem(QTcpSocket *socket, const QString &menuItemId, const QString &body)
{
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    
    if (error.error != QJsonParseError::NoError) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Invalid JSON";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    QJsonObject request = doc.object();
    QString foodType = request["foodType"].toString();
    QString foodName = request["foodName"].toString();
    QString foodDetails = request["foodDetails"].toString();
    int price = request["price"].toInt();
    
    if (foodType.isEmpty() || foodName.isEmpty() || foodDetails.isEmpty() || price <= 0) {
        QJsonObject errorResponse;
        errorResponse["error"] = "All fields are required and price must be positive";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    
    if (updateMenuItem(menuItemId, foodType, foodName, foodDetails, price)) {
        QJsonObject response;
        response["message"] = "Menu item updated successfully";
        sendJsonResponse(socket, 200, response);
    } else {
        QJsonObject errorResponse;
        errorResponse["error"] = "Failed to update menu item";
        sendJsonResponse(socket, 500, errorResponse);
    }
}

void HttpServer::handleDeleteMenuItem(QTcpSocket *socket, const QString &menuItemId)
{
    if (deleteMenuItem(menuItemId)) {
        QJsonObject response;
        response["message"] = "Menu item deleted successfully";
        sendJsonResponse(socket, 200, response);
    } else {
        QJsonObject errorResponse;
        errorResponse["error"] = "Failed to delete menu item";
        sendJsonResponse(socket, 500, errorResponse);
    }
}

void HttpServer::handleSetUserRestaurant(QTcpSocket *socket, const QString &body) {
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError) {
        QJsonObject errorResponse;
        errorResponse["error"] = "Invalid JSON";
        sendJsonResponse(socket, 400, errorResponse);
        return;
    }
    QJsonObject req = doc.object();
    int userId = req["userId"].toInt();
    int restaurantId = req["restaurantId"].toInt();
    qInfo() << "[DEBUG] handleSetUserRestaurant: userId=" << userId << "restaurantId=" << restaurantId;
    QSqlQuery query;
    query.prepare("UPDATE users SET restaurant_id = ? WHERE id = ?");
    query.addBindValue(restaurantId);
    query.addBindValue(userId);
    if (query.exec()) {
        qInfo() << "[DEBUG] Updated users table for userId=" << userId << "restaurantId=" << restaurantId;
        sendJsonResponse(socket, 200, QJsonObject{{"message", "Updated"}});
    } else {
        qWarning() << "[DEBUG] Failed to update users table:" << query.lastError().text();
        sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to update"}});
    }
}

void HttpServer::handleCreateRestaurant(QTcpSocket *socket, const QString &body) {
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError) {
        sendJsonResponse(socket, 400, QJsonObject{{"error", "Invalid JSON"}});
        return;
    }
    QJsonObject req = doc.object();
    QString name = req["name"].toString();
    QString type = req["type"].toString();
    QString location = req["location"].toString();
    QString description = req["description"].toString();
    int minPrice = req["minPrice"].toInt();
    int maxPrice = req["maxPrice"].toInt();

    // Try to get userId from JSON, or look up by username
    int userId = req["userId"].toInt();
    if (userId == 0 && req.contains("username")) {
        QString username = req["username"].toString();
        QSqlQuery userQuery;
        userQuery.prepare("SELECT id FROM users WHERE username = ?");
        userQuery.addBindValue(username);
        if (userQuery.exec() && userQuery.next()) {
            userId = userQuery.value(0).toInt();
        } else {
            sendJsonResponse(socket, 400, QJsonObject{{"error", "User not found"}});
            return;
        }
    }
    if (userId == 0) {
        sendJsonResponse(socket, 400, QJsonObject{{"error", "Missing userId or username"}});
        return;
    }

    QSqlQuery query;
    query.prepare("INSERT INTO restaurants (name, type, location, description, min_price, max_price) VALUES (?, ?, ?, ?, ?, ?)");
    query.addBindValue(name);
    query.addBindValue(type);
    query.addBindValue(location);
    query.addBindValue(description);
    query.addBindValue(minPrice);
    query.addBindValue(maxPrice);

    if (!query.exec()) {
        sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to create restaurant"}});
        return;
    }
    int restaurantId = query.lastInsertId().toInt();

    QSqlQuery updateUser;
    updateUser.prepare("UPDATE users SET restaurant_id = ? WHERE id = ?");
    updateUser.addBindValue(restaurantId);
    updateUser.addBindValue(userId);
    if (!updateUser.exec()) {
        sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to link user"}});
        return;
    }

    sendJsonResponse(socket, 200, QJsonObject{{"restaurantId", restaurantId}});
}

bool HttpServer::initializeDatabase()
{
    QSqlDatabase db = QSqlDatabase::database();
    if (!db.isOpen()) {
        qCritical() << "Database not open";
        return false;
    }
    
    // Create tables if they don't exist
    QSqlQuery query;
    
    // Users table
    if (!query.exec("CREATE TABLE IF NOT EXISTS users ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                   "username TEXT NOT NULL UNIQUE,"
                   "password TEXT NOT NULL,"
                   "user_type TEXT NOT NULL CHECK(user_type IN ('customer', 'manager', 'restaurant')),"
                   "restaurant_id INTEGER,"
                   "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                   ");")) {
        qCritical() << "Failed to create users table:" << query.lastError().text();
        return false;
    }
    
    // Restaurants table
    if (!query.exec("CREATE TABLE IF NOT EXISTS restaurants ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                   "name TEXT NOT NULL,"
                   "type TEXT NOT NULL,"
                   "location TEXT NOT NULL,"
                   "description TEXT,"
                   "min_price INTEGER NOT NULL,"
                   "max_price INTEGER NOT NULL,"
                   "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                   ");")) {
        qCritical() << "Failed to create restaurants table:" << query.lastError().text();
        return false;
    }
    
    // Menu items table
    if (!query.exec("CREATE TABLE IF NOT EXISTS menu_items ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                   "restaurant_id INTEGER,"
                   "food_type TEXT NOT NULL,"
                   "food_name TEXT NOT NULL,"
                   "food_details TEXT NOT NULL,"
                   "price INTEGER NOT NULL,"
                   "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                   ");")) {
        qCritical() << "Failed to create menu_items table:" << query.lastError().text();
        return false;
    }
    
    // Orders table
    if (!query.exec("CREATE TABLE IF NOT EXISTS orders ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                   "customer_id INTEGER,"
                   "restaurant_id INTEGER,"
                   "total_amount INTEGER NOT NULL,"
                   "order_status TEXT DEFAULT 'pending',"
                   "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                   ");")) {
        qCritical() << "Failed to create orders table:" << query.lastError().text();
        return false;
    }
    
    // Order items table
    if (!query.exec("CREATE TABLE IF NOT EXISTS order_items ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                   "order_id INTEGER,"
                   "menu_item_id INTEGER,"
                   "quantity INTEGER NOT NULL,"
                   "price INTEGER NOT NULL,"
                   "FOREIGN KEY (order_id) REFERENCES orders(id),"
                   "FOREIGN KEY (menu_item_id) REFERENCES menu_items(id)"
                   ");")) {
        qCritical() << "Failed to create order_items table:" << query.lastError().text();
        return false;
    }
    
    // Insert sample data if tables are empty
    QSqlQuery checkQuery("SELECT COUNT(*) FROM restaurants");
    if (checkQuery.exec() && checkQuery.next() && checkQuery.value(0).toInt() == 0) {
        // Insert sample restaurants
        query.exec("INSERT INTO restaurants (name, type, location, description, min_price, max_price) VALUES "
                  "('Shaher', 'Fast Food', 'esfahanunivercity-sheikhbahaie-34', 'Delicious fast food restaurant', 500000, 600000),"
                  "('Aseman', 'Iranian', 'esfahanunivercity-sheikhbahaie-12', 'Authentic Iranian cuisine', 10000, 100000)");
        
        // Insert sample menu items
        query.exec("INSERT INTO menu_items (restaurant_id, food_type, food_name, food_details, price) VALUES "
                  "(1, 'Main Course', 'Classic Burger', 'Juicy beef burger with fresh vegetables', 25000),"
                  "(1, 'Appetizer', 'French Fries', 'Crispy golden fries', 15000),"
                  "(2, 'Main Course', 'Kebab', 'Traditional Iranian kebab', 30000)");
        
        // Insert sample users
        query.exec("INSERT INTO users (username, password, user_type, restaurant_id) VALUES "
                  "('restaurant1', 'password123', 'restaurant', 1),"
                  "('restaurant2', 'password123', 'restaurant', 2),"
                  "('customer1', 'password123', 'customer', NULL),"
                  "('manager1', 'password123', 'manager', NULL)");
    }
    
    qInfo() << "Database initialized successfully";
    return true;
}

QJsonObject HttpServer::authenticateUser(const QString &username, const QString &password)
{
    QSqlQuery query;
    query.prepare("SELECT id, username, user_type, restaurant_id FROM users WHERE username = ? AND password = ?");
    query.addBindValue(username);
    query.addBindValue(password);
    
    if (query.exec() && query.next()) {
        QJsonObject userInfo;
        userInfo["id"] = query.value(0).toInt();
        userInfo["username"] = query.value(1).toString();
        userInfo["userType"] = query.value(2).toString();
        userInfo["restaurantId"] = query.value(3).toInt();
        return userInfo;
    } else {
        QJsonObject error;
        error["error"] = "Invalid username or password";
        return error;
    }
}

bool HttpServer::registerUser(const QString &username, const QString &password, const QString &userType)
{
    QSqlQuery query;
    if (userType == "restaurant") {
        // Insert user first
        query.prepare("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)");
        query.addBindValue(username);
        query.addBindValue(password);
        query.addBindValue(userType);
        if (!query.exec()) {
            return false;
        }
        int userId = query.lastInsertId().toInt();
        // Insert restaurant with id = userId
        QSqlQuery restQuery;
        restQuery.prepare("INSERT INTO restaurants (id, name, type, location, description, min_price, max_price) VALUES (?, ?, ?, ?, ?, ?, ?)");
        restQuery.addBindValue(userId);
        restQuery.addBindValue("New Restaurant");
        restQuery.addBindValue("Unknown");
        restQuery.addBindValue("Unknown");
        restQuery.addBindValue("");
        restQuery.addBindValue(0);
        restQuery.addBindValue(0);
        if (!restQuery.exec()) {
            // Rollback user if restaurant insert fails
            QSqlQuery delUser;
            delUser.prepare("DELETE FROM users WHERE id = ?");
            delUser.addBindValue(userId);
            delUser.exec();
            return false;
        }
        // Update user's restaurant_id
        QSqlQuery updateUser;
        updateUser.prepare("UPDATE users SET restaurant_id = ? WHERE id = ?");
        updateUser.addBindValue(userId);
        updateUser.addBindValue(userId);
        if (!updateUser.exec()) {
            return false;
        }
        return true;
    } else {
        query.prepare("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)");
        query.addBindValue(username);
        query.addBindValue(password);
        query.addBindValue(userType);
        return query.exec();
    }
}

QJsonArray HttpServer::getRestaurantsList()
{
    QJsonArray restaurants;
    QSqlQuery query("SELECT id, name, type, location, description, min_price, max_price FROM restaurants ORDER BY name");
    
    if (query.exec()) {
        while (query.next()) {
            QJsonObject restaurant;
            restaurant["id"] = query.value(0).toInt();
            restaurant["name"] = query.value(1).toString();
            restaurant["type"] = query.value(2).toString();
            restaurant["location"] = query.value(3).toString();
            restaurant["description"] = query.value(4).toString();
            restaurant["minPrice"] = query.value(5).toInt();
            restaurant["maxPrice"] = query.value(6).toInt();
            restaurants.append(restaurant);
        }
    }
    
    return restaurants;
}

QJsonArray HttpServer::getMenuItems(const QString &restaurantId)
{
    QJsonArray menu;
    QSqlQuery query;
    query.prepare("SELECT id, food_type, food_name, food_details, price FROM menu_items WHERE restaurant_id = ? ORDER BY food_type, food_name");
    query.addBindValue(restaurantId.toInt());
    
    if (query.exec()) {
        while (query.next()) {
            QJsonObject item;
            item["id"] = query.value(0).toInt();
            item["foodType"] = query.value(1).toString();
            item["foodName"] = query.value(2).toString();
            item["foodDetails"] = query.value(3).toString();
            item["price"] = query.value(4).toInt();
            menu.append(item);
        }
    }
    
    return menu;
}

bool HttpServer::createOrder(const QString &customerId, const QString &restaurantId, const QJsonArray &items, int totalAmount)
{
    QSqlDatabase db = QSqlDatabase::database();
    db.transaction();
    
    try {
        // Create order
        QSqlQuery orderQuery;
        orderQuery.prepare("INSERT INTO orders (customer_id, restaurant_id, total_amount) VALUES (?, ?, ?)");
        orderQuery.addBindValue(customerId.toInt());
        orderQuery.addBindValue(restaurantId.toInt());
        orderQuery.addBindValue(totalAmount);
        
        if (!orderQuery.exec()) {
            db.rollback();
            return false;
        }
        
        int orderId = orderQuery.lastInsertId().toInt();
        
        // Create order items
        for (const QJsonValue &itemValue : items) {
            QJsonObject item = itemValue.toObject();
            QSqlQuery itemQuery;
            itemQuery.prepare("INSERT INTO order_items (order_id, menu_item_id, quantity, price) VALUES (?, ?, ?, ?)");
            itemQuery.addBindValue(orderId);
            itemQuery.addBindValue(item["menuItemId"].toInt());
            itemQuery.addBindValue(item["quantity"].toInt());
            itemQuery.addBindValue(item["price"].toInt());
            
            if (!itemQuery.exec()) {
                db.rollback();
                return false;
            }
        }
        
        db.commit();
        return true;
    } catch (...) {
        db.rollback();
        return false;
    }
}

QJsonArray HttpServer::getOrders(const QString &userId, const QString &userType)
{
    QJsonArray orders;
    QSqlQuery query;
    
    if (userType == "restaurant") {
        query.prepare("SELECT o.id, u.username, o.total_amount, o.order_status, o.created_at "
                     "FROM orders o "
                     "JOIN users u ON o.customer_id = u.id "
                     "WHERE o.restaurant_id = (SELECT restaurant_id FROM users WHERE id = ?) "
                     "ORDER BY o.created_at DESC");
        query.addBindValue(userId.toInt());
    } else {
        query.prepare("SELECT o.id, r.name as restaurant_name, o.total_amount, o.order_status, o.created_at "
                     "FROM orders o "
                     "JOIN restaurants r ON o.restaurant_id = r.id "
                     "WHERE o.customer_id = ? "
                     "ORDER BY o.created_at DESC");
        query.addBindValue(userId.toInt());
    }
    
    if (query.exec()) {
        while (query.next()) {
            QJsonObject order;
            order["id"] = query.value(0).toInt();
            order["customerName"] = query.value(1).toString();
            order["totalAmount"] = query.value(2).toInt();
            order["status"] = query.value(3).toString();
            order["createdAt"] = query.value(4).toString();
            orders.append(order);
        }
    }
    
    return orders;
}

bool HttpServer::updateOrderStatus(const QString &orderId, const QString &status)
{
    QSqlQuery query;
    query.prepare("UPDATE orders SET order_status = ? WHERE id = ?");
    query.addBindValue(status);
    query.addBindValue(orderId.toInt());
    
    return query.exec();
}

bool HttpServer::addMenuItem(const QString &restaurantId, const QString &foodType, const QString &foodName, const QString &foodDetails, int price)
{
    QSqlQuery query;
    query.prepare("INSERT INTO menu_items (restaurant_id, food_type, food_name, food_details, price) VALUES (?, ?, ?, ?, ?)");
    query.addBindValue(restaurantId.toInt());
    query.addBindValue(foodType);
    query.addBindValue(foodName);
    query.addBindValue(foodDetails);
    query.addBindValue(price);
    
    return query.exec();
}

bool HttpServer::updateMenuItem(const QString &menuItemId, const QString &foodType, const QString &foodName, const QString &foodDetails, int price)
{
    QSqlQuery query;
    query.prepare("UPDATE menu_items SET food_type = ?, food_name = ?, food_details = ?, price = ? WHERE id = ?");
    query.addBindValue(foodType);
    query.addBindValue(foodName);
    query.addBindValue(foodDetails);
    query.addBindValue(price);
    query.addBindValue(menuItemId.toInt());
    
    return query.exec();
}

bool HttpServer::deleteMenuItem(const QString &menuItemId)
{
    QSqlQuery query;
    query.prepare("DELETE FROM menu_items WHERE id = ?");
    query.addBindValue(menuItemId.toInt());
    
    return query.exec();
}

void HttpServer::handleGetUserInfo(QTcpSocket *socket, const QString &userId) {
    QSqlQuery query;
    query.prepare("SELECT id, username, user_type, restaurant_id, created_at FROM users WHERE id = ?");
    query.addBindValue(userId.toInt());
    if (query.exec() && query.next()) {
        QJsonObject userInfo;
        userInfo["id"] = query.value(0).toInt();
        userInfo["username"] = query.value(1).toString();
        userInfo["userType"] = query.value(2).toString();
        userInfo["restaurantId"] = query.value(3).isNull() ? QJsonValue() : QJsonValue(query.value(3).toInt());
        userInfo["createdAt"] = query.value(4).toString();
        sendJsonResponse(socket, 200, userInfo);
    } else {
        sendJsonResponse(socket, 404, QJsonObject{{"error", "User not found"}});
    }
}