#include "credentials.h"


std::ostream& operator<<(std::ostream& os, const Credentials& cred)
{
    os <<" Service:  "<< cred.service <<"\n" 
       <<" Login:    "<< cred.login <<"\n"
       <<" Password: "<< cred.password<<std::endl;
    return os;
}