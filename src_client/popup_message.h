#ifndef POPUP_MESSAGE_H
#define POPUP_MESSAGE_H

#include <string>

class PopupMessage
{
public:
    enum  MessageType{
        InfoMessage,
        ErrorMessage
    };
    PopupMessage(MessageType type, std::string message);

    void Show();
    bool IsActive() const;
private:
    bool isActive_;

    MessageType type_;
    std::string message_;
    std::string title_;
};

#endif /* POPUP_MESSAGE_H */
