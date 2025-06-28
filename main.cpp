#include <QCoreApplication>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSqlDatabase>
#include <QDebug>
#include <QTextStream>
#include <QByteArray>

class HttpServer : public QObject
{
    Q_OBJECT

public:
    HttpServer(QObject *parent = nullptr) : QObject(parent), server(this)
    {
        connect(&server, &QTcpServer::newConnection, this, &HttpServer::handleNewConnection);
    }

    bool listen(const QHostAddress &address, quint16 port)
    {
        return server.listen(address, port);
    }

private slots:
    void handleNewConnection()
    {
        QTcpSocket *socket = server.nextPendingConnection();
        qInfo() << "New connection from:" << socket->peerAddress().toString();
        connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
            handleRequest(socket);
        });
        connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
    }

    void handleRequest(QTcpSocket *socket)
    {
        QByteArray request = socket->readAll();
        QString requestStr = QString::fromUtf8(request);
        
        qInfo() << "Received request:" << requestStr.split("\r\n").first();
        
        // Simple HTTP request parsing
        QStringList lines = requestStr.split("\r\n");
        if (lines.isEmpty()) return;
        
        QString firstLine = lines[0];
        QStringList parts = firstLine.split(" ");
        if (parts.size() < 2) return;
        
        QString method = parts[0];
        QString path = parts[1];
        
        qInfo() << "Request:" << method << path;
        
        // Handle different routes
        QString response;
        if (path == "/api/health") {
            response = "HTTP/1.1 200 OK\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: 25\r\n"
                      "\r\n"
                      "{\"status\": \"Server is running\"}";
            qInfo() << "Sending health check response";
        } else {
            response = "HTTP/1.1 404 Not Found\r\n"
                      "Content-Type: text/plain\r\n"
                      "Content-Length: 13\r\n"
                      "\r\n"
                      "404 Not Found";
            qInfo() << "Sending 404 response for path:" << path;
        }
        
        socket->write(response.toUtf8());
        socket->flush();
        socket->close();
    }

private:
    QTcpServer server;
};

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

    return app.exec();
}

#include "main.moc"
