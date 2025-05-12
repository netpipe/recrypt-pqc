#include <QCoreApplication>
#include <QDebug>
#include "rsa_qt.h"

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);

    RSA rsa;
    RSA::Key pub = rsa.getPublicKey();
    RSA::Key priv = rsa.getPrivateKey();

    QByteArray message = "Hello, Qt RSA!";
    QByteArray encrypted = rsa.encrypt(message, pub);
    QByteArray decrypted = rsa.decrypt(encrypted, priv);

    qDebug() << "Original:" << message;
    qDebug() << "Decrypted:" << decrypted;

    return a.exec();
}
