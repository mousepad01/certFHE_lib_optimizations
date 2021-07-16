#include "Plaintext.h"

using namespace certFHE;

namespace certFHE {

#pragma region Operators

    std::ostream& operator<<(std::ostream &out, const Plaintext &c)
{
   
    char val = c.getValue();
    val = val | 0x30;
    out<<val;
    out<<'\n';
    return out;

}

#pragma endregion

#pragma region Constructors and destructor
   
    Plaintext::Plaintext()
    {
        this->value = 0x00;
    }

    Plaintext::Plaintext(uint64_t value) : Plaintext()
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
        return this->value;
    }

    void Plaintext::setValue(unsigned char value)
    {
        this->value = value & 0x01;
    }

#pragma endregion

}