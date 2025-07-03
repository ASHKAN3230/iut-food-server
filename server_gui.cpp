#include "server_gui.h"
#include "ui_server_gui.h"
#include <QHostAddress>
#include <QMessageBox>

ServerGUI::ServerGUI(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::ServerGUI)
{
    ui->setupUi(this);
    ui->addressLineEdit->setText("127.0.0.1");
    ui->portLineEdit->setText("8080");
    connect(ui->startButton, &QPushButton::clicked, this, &ServerGUI::on_startButton_clicked);
    connect(ui->stopButton, &QPushButton::clicked, this, &ServerGUI::on_stopButton_clicked);
    ui->stopButton->setEnabled(false);
}

ServerGUI::~ServerGUI()
{
    delete ui;
}

void ServerGUI::appendLog(const QString &msg)
{
    ui->logsTextEdit->append(msg);
}

QString ServerGUI::getAddress() const {
    return ui->addressLineEdit->text().trimmed();
}

quint16 ServerGUI::getPort() const {
    return ui->portLineEdit->text().trimmed().toUShort();
}

void ServerGUI::on_startButton_clicked()
{
    if (serverRunning) return;
    QString address = ui->addressLineEdit->text().trimmed();
    QString portStr = ui->portLineEdit->text().trimmed();
    bool ok = false;
    quint16 port = portStr.toUShort(&ok);
    if (!ok || port == 0) {
        QMessageBox::warning(this, "Invalid Port", "Please enter a valid port number.");
        return;
    }
    emit startServer();
    appendLog(QString("Server started at %1:%2").arg(address).arg(port));
    serverRunning = true;
    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);
}

void ServerGUI::on_stopButton_clicked()
{
    if (!serverRunning) return;
    emit stopServer();
    appendLog("Server stopped.");
    serverRunning = false;
    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
} 