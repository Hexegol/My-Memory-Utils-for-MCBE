#include "vector3.h"
#include <cmath>  
#include <iostream>
Vector3 Vector3::operator-(const Vector3& other) const
{
    return Vector3(x_ - other.x_, y_ - other.y_, z_ - other.z_);
}

void Vector3::Show()
{
    std::cout << x_ << " " << y_ << " " << z_ << "\n";
}

float Vector3::Distance(const Vector3& other) const {
    return sqrt((x_ - other.x_) * (x_ - other.x_) +
                (y_ - other.y_) * (y_ - other.y_) +
                (z_ - other.z_) * (z_ - other.z_));
}

bool Vector3::operator!=(const Vector3& other) const {
    return x_ != other.x_ || y_ != other.y_ || z_ != other.z_;
}


bool Vector3::isValid() const {
    return std::isfinite(x_) && std::isfinite(y_) && std::isfinite(z_);
}
