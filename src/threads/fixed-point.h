#ifndef THREADS_FIXED_POINT_H

#include <stdint.h>

# define FP_P 17
# define FP_Q 14
# define FP_F (1 << FP_P)

#define convert_to_fixed_point(n) (n * FP_F)

#define convert_to_integer_zero(x) (x / FP_F)

#define convert_to_integer_nearest(x) (x >= 0 ? (x + FP_F / 2) / FP_F : (x - FP_F / 2) / FP_F)

#define add_fixed_point(x, y) (x + y)

#define sub_fixed_point(x, y) (x - y)

#define add_fixed_point_to_integer(x, n) (x + n * FP_F)

#define sub_integer_from_fixed_point(x, n) (x - n * FP_F)

#define mul_fixed_point(x, y) (((int64_t) x) * y / FP_F)

#define mul_fixed_point_by_integer(x, n) (x * n)

#define div_fixed_point(x, y) (((int64_t) x) * FP_F / y)

#define div_fixed_point_by_integer(x, n) (x / n)

#endif
