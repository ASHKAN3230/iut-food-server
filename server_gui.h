#ifndef SERVER_GUI_H
#define SERVER_GUI_H

#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class ServerGUI; }
QT_END_NAMESPACE

class ServerGUI : public QWidget
{
    Q_OBJECT
public:
    explicit ServerGUI(QWidget *parent = nullptr);
    ~ServerGUI();

    void appendLog(const QString &msg);
    QString getAddress() const;
    quint16 getPort() const;

private slots:
    void on_startButton_clicked();
    void on_stopButton_clicked();

signals:
    void startServer();
    void stopServer();

private:
    Ui::ServerGUI *ui;
    bool serverRunning = false;
};

#endif // SERVER_GUI_H 