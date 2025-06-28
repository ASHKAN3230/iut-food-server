#include <QCoreApplication>
#include <QSqlDatabase>
#include <QDebug>
#include "httpserver.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

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

    // Create HTTP server
    HttpServer server;

    // Start server
    const auto port = 8080;
    if (!server.listen(QHostAddress::Any, port)) {
        qCritical() << "Failed to start server on port" << port;
        return -1;
    }

    qInfo() << "Server started successfully on port" << port;
    qInfo() << "Server is running. Press Ctrl+C to stop.";
    qInfo() << "";
    qInfo() << "Available API endpoints:";
    qInfo() << "  GET  /api/health                    - Health check";
    qInfo() << "  POST /api/auth/login               - User login";
    qInfo() << "  POST /api/auth/register            - User registration";
    qInfo() << "  GET  /api/restaurants              - Get all restaurants";
    qInfo() << "  GET  /api/restaurants/{id}/menu    - Get restaurant menu";
    qInfo() << "  POST /api/orders                   - Create new order";
    qInfo() << "  GET  /api/orders                   - Get user orders";
    qInfo() << "  PUT  /api/orders/{id}              - Update order status";
    qInfo() << "";

    return app.exec();
}
