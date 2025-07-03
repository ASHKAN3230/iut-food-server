#include <QApplication>
#include <QSqlDatabase>
#include <QDebug>
#include "httpserver.h"
#include "server_gui.h"
#include <QHostAddress>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    ServerGUI w;
    HttpServer server;

    QObject::connect(&server, &HttpServer::logMessage, &w, &ServerGUI::appendLog);

    QObject::connect(&w, &ServerGUI::startServer, [&]() {
        QString address = w.getAddress();
        quint16 port = w.getPort();
        server.listen(QHostAddress(address), port);
    });
    QObject::connect(&w, &ServerGUI::stopServer, [&]() {
        server.close();
        w.appendLog("Server stopped.");
    });

    w.show();

    // Set application info
    app.setApplicationName("IUT Food Server");
    app.setApplicationVersion("1.0.0");

    qInfo() << "Starting IUT Food Server...";

    // Initialize database
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("iut_food_server.db");

    if (!db.open()) {
        qCritical() << "Failed to open database: Unable to connect to SQLite database";
        return -1;
    }

    qInfo() << "Database connected successfully";

    qInfo() << "Server is running. Press Ctrl+C to stop.";
    qInfo() << "";
    qInfo() << "Available API endpoints:";
    qInfo() << "  GET   /api/health                       - Health check";
    qInfo() << "  POST  /api/auth/login                  - User login";
    qInfo() << "  POST  /api/auth/register               - User registration";
    qInfo() << "  GET   /api/restaurants                 - Get all restaurants";
    qInfo() << "  GET   /api/restaurants/{id}/menu       - Get restaurant menu";
    qInfo() << "  POST  /api/restaurants/create          - Create new restaurant";
    qInfo() << "  POST  /api/orders                      - Create new order";
    qInfo() << "  GET   /api/orders?userId=&userType=    - Get user orders";
    qInfo() << "  PUT   /api/orders/{id}                 - Update order status";
    qInfo() << "  POST  /api/menu                        - Add menu item";
    qInfo() << "  PUT   /api/menu/{id}                   - Update menu item";
    qInfo() << "  DELETE /api/menu/{id}                  - Delete menu item";
    qInfo() << "  POST  /api/users/set-restaurant        - Set user's restaurant (for restaurant users)";
    qInfo() << "  GET   /api/users/{id}                  - Get user info";
    qInfo() << "  GET   /api/debug/orders                - Debug: get all orders (admin)";
    qInfo() << "";

    return app.exec();
}
