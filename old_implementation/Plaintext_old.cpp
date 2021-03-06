#include "Plaintext_old.h"

using namespace certFHE_old;
using namespace std;

namespace certFHE_old {

#pragma region Operators

ostream& operator<<(ostream &out, const Plaintext &c)
{
   
    char val = c.getValue();
    val = val | 0x30;
    out<<val;
    out<<endl;
    return out;

}

#pragma endregion

#pragma region Constructors and destructor
   
Plaintext::Plaintext()
{
    this->value = 0x00;
}

Plaintext::Plaintext(const int value) : Plaintext()
{
    this->value = BIT(value);
}

Plaintext::~Plaintext()
{

}

#pragma endregion

#pragma region Getters and setters

unsigned char Plaintext::getValue() const
{
    return this->value & 0x01;
}

void Plaintext::setValue(unsigned char value)
{
    this->value = value & 0x01;
}

#pragma endregion

}