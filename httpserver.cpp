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
        // Parse userId and userType from query string
        QUrl url("http://localhost" + path);
        QUrlQuery query(url);
        QString userId = query.queryItemValue("userId");
        QString userType = query.queryItemValue("userType");
        if (userId.isEmpty() || userType.isEmpty()) {
            sendJsonResponse(socket, 400, QJsonObject{{"error", "Missing userId or userType"}});
            return;
        }
        handleGetOrders(socket, userId, userType);
    } else if (path.startsWith("/api/orders/") && path.endsWith("/rate") && method == "PUT") {
        QString orderId = path.split("/")[3];
        handleRateOrder(socket, orderId, body);
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
    } else if (path == "/api/debug/orders" && method == "GET") {
        handleDebugOrders(socket);
    } else if (path.startsWith("/api/users/") && method == "GET") {
        // /api/users/{id}
        QStringList pathParts = path.split("/");
        if (pathParts.size() >= 4) {
            QString userId = pathParts[3];
            handleGetUserInfo(socket, userId);
        } else {
            sendJsonResponse(socket, 400, QJsonObject{{"error", "Missing user id"}});
        }
    } else if (path == "/api/restaurants/pending-auth" && method == "GET") {
        handleGetPendingAuthRestaurants(socket);
    } else if (path == "/api/restaurants/auth-status" && method == "POST") {
        handleSetRestaurantAuthStatus(socket, body);
    } else if (path == "/api/forgot-password" && method == "POST") {
        handleForgotPassword(socket, body);
    } else if (path.startsWith("/api/restaurants/") && method == "DELETE") {
        // /api/restaurants/{id}
        QStringList pathParts = path.split("/");
        if (pathParts.size() >= 4) {
            QString restaurantId = pathParts[3];
            handleDeleteRestaurant(socket, restaurantId);
        } else {
            sendJsonResponse(socket, 400, QJsonObject{{"error", "Missing restaurant id"}});
        }
    } else if (path.startsWith("/api/users/") && method == "DELETE") {
        // /api/users/{id}
        QStringList pathParts = path.split("/");
        if (pathParts.size() >= 4) {
            QString userId = pathParts[3];
            handleDeleteUser(socket, userId);
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

void HttpServer::handleGetOrders(QTcpSocket *socket, const QString &userId, const QString &userType)
{
    qInfo() << "[DEBUG] handleGetOrders called with userId:" << userId << "userType:" << userType;
    QJsonArray orders = getOrders(userId, userType);
    qInfo() << "[DEBUG] handleGetOrders returning" << orders.size() << "orders";
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
    query.prepare("INSERT INTO restaurant_applications (user_id, name, type, location, description, min_price, max_price) VALUES (?, ?, ?, ?, ?, ?, ?)");
    query.addBindValue(userId);
    query.addBindValue(name);
    query.addBindValue(type);
    query.addBindValue(location);
    query.addBindValue(description);
    query.addBindValue(minPrice);
    query.addBindValue(maxPrice);

    if (!query.exec()) {
        sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to submit application"}});
        return;
    }
    int applicationId = query.lastInsertId().toInt();
    sendJsonResponse(socket, 200, QJsonObject{{"applicationId", applicationId}});
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
                   "is_auth INTEGER DEFAULT 0,"
                   "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                   ");")) {
        qCritical() << "Failed to create restaurants table:" << query.lastError().text();
        return false;
    }
    query.exec("ALTER TABLE restaurants ADD COLUMN is_auth INTEGER DEFAULT 0");
    
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
    query.exec("ALTER TABLE orders ADD COLUMN rating INTEGER DEFAULT 0");
    query.exec("ALTER TABLE orders ADD COLUMN comment TEXT");
    
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
    
    // Add after users and restaurants table creation
    query.exec("CREATE TABLE IF NOT EXISTS restaurant_applications ("
               "id INTEGER PRIMARY KEY AUTOINCREMENT,"
               "user_id INTEGER NOT NULL,"
               "name TEXT NOT NULL,"
               "type TEXT NOT NULL,"
               "location TEXT NOT NULL,"
               "description TEXT,"
               "min_price INTEGER NOT NULL,"
               "max_price INTEGER NOT NULL,"
               "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
               ");");
    
    // Ensure default admin/manager account exists
    QSqlQuery adminCheckQuery;
    adminCheckQuery.prepare("SELECT COUNT(*) FROM users WHERE username = ? AND user_type = 'manager'");
    adminCheckQuery.addBindValue("admin");
    if (adminCheckQuery.exec() && adminCheckQuery.next() && adminCheckQuery.value(0).toInt() == 0) {
        QSqlQuery insertAdminQuery;
        insertAdminQuery.prepare("INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)");
        insertAdminQuery.addBindValue("admin");
        insertAdminQuery.addBindValue("admin");
        insertAdminQuery.addBindValue("manager");
        if (insertAdminQuery.exec()) {
            qInfo() << "Default admin/manager account created: username='admin', password='admin'";
        } else {
            qWarning() << "Failed to create default admin/manager account:" << insertAdminQuery.lastError().text();
        }
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
        
        // Insert sample orders
        query.exec("INSERT INTO orders (customer_id, restaurant_id, total_amount, order_status, created_at) VALUES "
                  "(3, 1, 40000, 'completed', datetime('now', '-2 days')),"
                  "(3, 2, 30000, 'pending', datetime('now', '-1 day')),"
                  "(3, 1, 25000, 'preparing', datetime('now', '-6 hours'))");
        
        // Insert sample order items
        query.exec("INSERT INTO order_items (order_id, menu_item_id, quantity, price) VALUES "
                  "(1, 1, 1, 25000),"
                  "(1, 2, 1, 15000),"
                  "(2, 3, 1, 30000),"
                  "(3, 1, 1, 25000)");
    }
    
    qInfo() << "Database initialized successfully";
    
    // Debug: Check if sample data exists
    QSqlQuery debugQuery;
    debugQuery.exec("SELECT COUNT(*) FROM orders");
    if (debugQuery.next()) {
        qInfo() << "[DEBUG] Total orders in database:" << debugQuery.value(0).toInt();
    }
    
    debugQuery.exec("SELECT COUNT(*) FROM users");
    if (debugQuery.next()) {
        qInfo() << "[DEBUG] Total users in database:" << debugQuery.value(0).toInt();
    }
    
    debugQuery.exec("SELECT COUNT(*) FROM restaurants");
    if (debugQuery.next()) {
        qInfo() << "[DEBUG] Total restaurants in database:" << debugQuery.value(0).toInt();
    }
    
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
    
    qInfo() << "[DEBUG] getOrders called with userId:" << userId << "userType:" << userType;
    
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
    
    qInfo() << "[DEBUG] Executing query:" << query.lastQuery();
    
    if (query.exec()) {
        qInfo() << "[DEBUG] Query executed successfully";
        while (query.next()) {
            QJsonObject order;
            order["id"] = query.value(0).toInt();
            if (userType == "restaurant") {
                order["customerName"] = query.value(1).toString();
            } else {
                order["restaurantName"] = query.value(1).toString();
            }
            order["totalAmount"] = query.value(2).toInt();
            order["status"] = query.value(3).toString();
            order["createdAt"] = query.value(4).toString();
            // Fetch rating
            QSqlQuery ratingQuery;
            ratingQuery.prepare("SELECT rating, comment FROM orders WHERE id = ?");
            ratingQuery.addBindValue(query.value(0).toInt());
            if (ratingQuery.exec() && ratingQuery.next()) {
                order["rating"] = ratingQuery.value(0).toInt();
                order["comment"] = ratingQuery.value(1).toString();
            } else {
                order["rating"] = 0;
                order["comment"] = "";
            }
            orders.append(order);
            qInfo() << "[DEBUG] Found order:" << order;
        }
        qInfo() << "[DEBUG] Total orders found:" << orders.size();
    } else {
        qWarning() << "[DEBUG] Query failed:" << query.lastError().text();
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
        if (userInfo["userType"].toString() == "restaurant") {
            int restId = query.value(3).isNull() ? -1 : query.value(3).toInt();
            bool isAuth = false;
            if (restId > 0) {
                QSqlQuery restQuery;
                restQuery.prepare("SELECT is_auth FROM restaurants WHERE id = ?");
                restQuery.addBindValue(restId);
                if (restQuery.exec() && restQuery.next()) {
                    isAuth = restQuery.value(0).toInt() == 1;
                }
            }
            userInfo["isAuth"] = isAuth;
        } else {
            userInfo["isAuth"] = false;
        }
        sendJsonResponse(socket, 200, userInfo);
    } else {
        sendJsonResponse(socket, 404, QJsonObject{{"error", "User not found"}});
    }
}

void HttpServer::handleDebugOrders(QTcpSocket *socket) {
    QJsonObject debugInfo;
    
    // Check orders table
    QSqlQuery query;
    query.exec("SELECT COUNT(*) FROM orders");
    if (query.next()) {
        debugInfo["totalOrders"] = query.value(0).toInt();
    }
    
    // Get all orders with details
    QJsonArray orders;
    query.exec("SELECT o.id, o.customer_id, o.restaurant_id, o.total_amount, o.order_status, o.created_at, "
               "u.username as customer_name, r.name as restaurant_name "
               "FROM orders o "
               "LEFT JOIN users u ON o.customer_id = u.id "
               "LEFT JOIN restaurants r ON o.restaurant_id = r.id");
    
    while (query.next()) {
        QJsonObject order;
        order["id"] = query.value(0).toInt();
        order["customerId"] = query.value(1).toInt();
        order["restaurantId"] = query.value(2).toInt();
        order["totalAmount"] = query.value(3).toInt();
        order["status"] = query.value(4).toString();
        order["createdAt"] = query.value(5).toString();
        order["customerName"] = query.value(6).toString();
        order["restaurantName"] = query.value(7).toString();
        orders.append(order);
    }
    
    debugInfo["orders"] = orders;
    
    // Check users table
    query.exec("SELECT COUNT(*) FROM users");
    if (query.next()) {
        debugInfo["totalUsers"] = query.value(0).toInt();
    }
    
    // Get all users
    QJsonArray users;
    query.exec("SELECT id, username, user_type, restaurant_id FROM users");
    while (query.next()) {
        QJsonObject user;
        user["id"] = query.value(0).toInt();
        user["username"] = query.value(1).toString();
        user["userType"] = query.value(2).toString();
        user["restaurantId"] = query.value(3).isNull() ? QJsonValue() : QJsonValue(query.value(3).toInt());
        users.append(user);
    }
    
    debugInfo["users"] = users;
    
    sendJsonResponse(socket, 200, debugInfo);
}

void HttpServer::handleGetPendingAuthRestaurants(QTcpSocket *socket) {
    QJsonArray pending;
    QSqlQuery query("SELECT id, user_id, name, type, location, description, min_price, max_price, created_at FROM restaurant_applications");
    while (query.next()) {
        QJsonObject obj;
        obj["id"] = query.value(0).toInt();
        obj["userId"] = query.value(1).toInt();
        obj["name"] = query.value(2).toString();
        obj["type"] = query.value(3).toString();
        obj["location"] = query.value(4).toString();
        obj["description"] = query.value(5).toString();
        obj["minPrice"] = query.value(6).toInt();
        obj["maxPrice"] = query.value(7).toInt();
        obj["createdAt"] = query.value(8).toString();
        pending.append(obj);
    }
    sendJsonResponse(socket, 200, pending);
}

void HttpServer::handleSetRestaurantAuthStatus(QTcpSocket *socket, const QString &body) {
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError) {
        sendJsonResponse(socket, 400, QJsonObject{{"error", "Invalid JSON"}});
        return;
    }
    QJsonObject req = doc.object();
    int applicationId = req["applicationId"].toInt();
    int is_auth = req["is_auth"].toInt();
    if (is_auth == 1) { // Approve
        // Get application data
        QSqlQuery getApp;
        getApp.prepare("SELECT user_id, name, type, location, description, min_price, max_price FROM restaurant_applications WHERE id = ?");
        getApp.addBindValue(applicationId);
        if (!getApp.exec() || !getApp.next()) {
            sendJsonResponse(socket, 404, QJsonObject{{"error", "Application not found"}});
            return;
        }
        int userId = getApp.value(0).toInt();
        QString name = getApp.value(1).toString();
        QString type = getApp.value(2).toString();
        QString location = getApp.value(3).toString();
        QString description = getApp.value(4).toString();
        int minPrice = getApp.value(5).toInt();
        int maxPrice = getApp.value(6).toInt();
        // Insert into restaurants
        QSqlQuery ins;
        ins.prepare("INSERT INTO restaurants (name, type, location, description, min_price, max_price, is_auth) VALUES (?, ?, ?, ?, ?, ?, 1)");
        ins.addBindValue(name);
        ins.addBindValue(type);
        ins.addBindValue(location);
        ins.addBindValue(description);
        ins.addBindValue(minPrice);
        ins.addBindValue(maxPrice);
        if (!ins.exec()) {
            sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to approve application"}});
            return;
        }
        int restaurantId = ins.lastInsertId().toInt();
        // Update user's restaurant_id
        QSqlQuery updUser;
        updUser.prepare("UPDATE users SET restaurant_id = ? WHERE id = ?");
        updUser.addBindValue(restaurantId);
        updUser.addBindValue(userId);
        updUser.exec();
        // Delete application
        QSqlQuery del;
        del.prepare("DELETE FROM restaurant_applications WHERE id = ?");
        del.addBindValue(applicationId);
        del.exec();
        sendJsonResponse(socket, 200, QJsonObject{{"message", "Application approved"}});
    } else { // Deny
        QSqlQuery del;
        del.prepare("DELETE FROM restaurant_applications WHERE id = ?");
        del.addBindValue(applicationId);
        del.exec();
        sendJsonResponse(socket, 200, QJsonObject{{"message", "Application denied"}});
    }
}

void HttpServer::handleForgotPassword(QTcpSocket *socket, const QString &body) {
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError) {
        qInfo() << "[ForgotPassword] Invalid JSON received";
        sendJsonResponse(socket, 400, QJsonObject{{"error", "Invalid JSON"}});
        return;
    }
    QJsonObject request = doc.object();
    QString username = request["username"].toString();
    QString password = request["password"].toString();
    qInfo() << "[ForgotPassword] Attempt for username:" << username;
    if (username.isEmpty() || password.isEmpty()) {
        qInfo() << "[ForgotPassword] Username or password is empty";
        sendJsonResponse(socket, 400, QJsonObject{{"error", "Username and password are required"}});
        return;
    }
    if (updateUserPassword(username, password)) {
        qInfo() << "[ForgotPassword] Password updated for username:" << username;
        sendJsonResponse(socket, 200, QJsonObject{{"message", "Password updated successfully"}});
    } else {
        qInfo() << "[ForgotPassword] Failed to update password for username:" << username;
        sendJsonResponse(socket, 400, QJsonObject{{"error", "Failed to update password (user may not exist)"}});
    }
}

bool HttpServer::updateUserPassword(const QString &username, const QString &newPassword) {
    QSqlQuery query;
    query.prepare("UPDATE users SET password = ? WHERE username = ?");
    query.addBindValue(newPassword);
    query.addBindValue(username);
    bool ok = query.exec();
    qInfo() << "[ForgotPassword] SQL exec for username:" << username << "ok?" << ok << "rows affected:" << query.numRowsAffected();
    if (!ok) {
        qWarning() << "[ForgotPassword] Failed to update password for" << username << ":" << query.lastError().text();
        return false;
    }
    return query.numRowsAffected() > 0;
}

void HttpServer::handleDeleteRestaurant(QTcpSocket *socket, const QString &restaurantId) {
    QSqlQuery query;
    query.prepare("DELETE FROM restaurants WHERE id = ?");
    query.addBindValue(restaurantId);
    if (query.exec() && query.numRowsAffected() > 0) {
        sendJsonResponse(socket, 200, QJsonObject{{"message", "Restaurant deleted successfully"}});
    } else {
        sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to delete restaurant or not found"}});
    }
}

void HttpServer::handleDeleteUser(QTcpSocket *socket, const QString &userId) {
    QSqlQuery query;
    query.prepare("DELETE FROM users WHERE id = ?");
    query.addBindValue(userId);
    if (query.exec() && query.numRowsAffected() > 0) {
        sendJsonResponse(socket, 200, QJsonObject{{"message", "User deleted successfully"}});
    } else {
        sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to delete user or not found"}});
    }
}

void HttpServer::handleRateOrder(QTcpSocket *socket, const QString &orderId, const QString &body) {
    qInfo() << "[RateOrder] Received body:" << body;
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(body.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError) {
        qWarning() << "[RateOrder] Invalid JSON error:" << error.errorString();
        sendJsonResponse(socket, 400, QJsonObject{{"error", "Invalid JSON"}});
        return;
    }
    QJsonObject req = doc.object();
    qInfo() << "[RateOrder] Parsed JSON object:" << req;
    int rating = req["rating"].toInt();
    qInfo() << "[RateOrder] Extracted rating:" << rating;
    QString comment = req.contains("comment") ? req["comment"].toString() : "";
    qInfo() << "[RateOrder] Extracted comment:" << comment;
    if (rating < 1 || rating > 5) {
        qWarning() << "[RateOrder] Invalid rating value:" << rating;
        sendJsonResponse(socket, 400, QJsonObject{{"error", "Rating must be between 1 and 5"}});
        return;
    }
    QSqlQuery query;
    query.prepare("UPDATE orders SET rating = ?, comment = ? WHERE id = ?");
    query.addBindValue(rating);
    query.addBindValue(comment);
    query.addBindValue(orderId);
    if (query.exec() && query.numRowsAffected() > 0) {
        qInfo() << "[RateOrder] Order rated successfully for orderId:" << orderId;
        sendJsonResponse(socket, 200, QJsonObject{{"message", "Order rated successfully"}});
    } else {
        qWarning() << "[RateOrder] Failed to rate order or not found. orderId:" << orderId << " SQL error:" << query.lastError().text();
        sendJsonResponse(socket, 500, QJsonObject{{"error", "Failed to rate order or not found"}});
    }
}