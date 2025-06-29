#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSqlDatabase>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

class HttpServer : public QObject
{
    Q_OBJECT

public:
    HttpServer(QObject *parent = nullptr);
    bool listen(const QHostAddress &address, quint16 port);

private slots:
    void handleNewConnection();
    void handleRequest(QTcpSocket *socket);

private:
    QTcpServer server;
    
    // Response helpers
    void sendResponse(QTcpSocket *socket, int statusCode, const QString &contentType, const QByteArray &body);
    void sendJsonResponse(QTcpSocket *socket, int statusCode, const QJsonObject &json);
    void sendJsonResponse(QTcpSocket *socket, int statusCode, const QJsonArray &json);
    
    // Route handlers
    void handleHealthCheck(QTcpSocket *socket);
    void handleUserLogin(QTcpSocket *socket, const QString &body);
    void handleUserRegister(QTcpSocket *socket, const QString &body);
    void handleGetRestaurants(QTcpSocket *socket);
    void handleGetMenu(QTcpSocket *socket, const QString &restaurantId);
    void handleCreateOrder(QTcpSocket *socket, const QString &body);
    void handleGetOrders(QTcpSocket *socket, const QString &userId);
    void handleUpdateOrderStatus(QTcpSocket *socket, const QString &orderId, const QString &body);
    void handleAddMenuItem(QTcpSocket *socket, const QString &body);
    void handleUpdateMenuItem(QTcpSocket *socket, const QString &menuItemId, const QString &body);
    void handleDeleteMenuItem(QTcpSocket *socket, const QString &menuItemId);
    void handleSetUserRestaurant(QTcpSocket *socket, const QString &body);
    void handleCreateRestaurant(QTcpSocket *socket, const QString &body);
    void handleGetUserInfo(QTcpSocket *socket, const QString &userId);
    // Database helpers
    bool initializeDatabase();
    QJsonObject authenticateUser(const QString &username, const QString &password);
    bool registerUser(const QString &username, const QString &password, const QString &userType);
    QJsonArray getRestaurantsList();
    QJsonArray getMenuItems(const QString &restaurantId);
    bool createOrder(const QString &customerId, const QString &restaurantId, const QJsonArray &items, int totalAmount);
    QJsonArray getOrders(const QString &userId, const QString &userType);
    bool updateOrderStatus(const QString &orderId, const QString &status);
    bool addMenuItem(const QString &restaurantId, const QString &foodType, const QString &foodName, const QString &foodDetails, int price);
    bool updateMenuItem(const QString &menuItemId, const QString &foodType, const QString &foodName, const QString &foodDetails, int price);
    bool deleteMenuItem(const QString &menuItemId);
};

#endif // HTTPSERVER_H