#include <stdint.h>

# define p 17
# define q 14
# define f (1 << q)

#define convert_to_fixed_point(n) (n * f)

#define convert_to_integer_zero(x) (x / f)

#define convert_to_integer_nearest(x) (x >= 0 ? (x + f / 2) / f : (x - f / 2) / f)

#define add_fixed_point(x, y) (x + y)

#define sub_fixed_point(x, y) (x - y)

#define add_fixed_point_to_integer(x, n) (x + n * f)

#define sub_integer_from_fixed_point(x, n) (x - n * f)

#define mul_fixed_point(x, y) (((int64_t) x) * y / f)

#define mul_fixed_point_by_integer(x, n) (x * n)

#define div_fixed_point(x, y) (((int64_t) x) * f / y)

#define div_fixed_point_by_integer(x, n) (x / n)
