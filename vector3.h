#ifndef VECTOR3_H
#define VECTOR3_H
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

class Vector3 {
public:
    float x_, y_, z_;

    Vector3(float x = 0, float y = 0, float z = 0) : x_(x), y_(y), z_(z) {}

    Vector3 operator-(const Vector3& other) const;
    float Distance(const Vector3& other) const;
    bool operator!=(const Vector3& other) const;
    bool isValid() const;
    void Show();
    Vector3 operator/(float value) const {
        return Vector3(x_ / value, y_ / value, z_ / value);
    }
    Vector3 operator*(float scalar) const {
        return Vector3(x_ * scalar, y_ * scalar, z_ * scalar);
    }

    friend Vector3 operator*(float scalar, const Vector3& vec) {
        return Vector3(vec.x_ * scalar, vec.y_ * scalar, vec.z_ * scalar);
    }

    Vector3 operator+(const Vector3& other) const {
        return Vector3(x_ + other.x_, y_ + other.y_, z_ + other.z_);
    }

    float length() const {
        return sqrtf(x_ * x_ + y_ * y_ + z_ * z_);
    }

    Vector3 normalized() const {
        float len = length();
        if (len > 0) {
            return *this / len;
        }
        return *this;
    }


    float lengthSquared() const {
        return (x_ * x_) + (y_ * y_) + (z_ * z_);
    }




};

#endif  // VECTOR3_H
