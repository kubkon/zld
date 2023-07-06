#include <assert.h>
#include <stdio.h>

extern _Thread_local int a;
extern int getA();

int getA2() {
  return a;
}

int main() {
  a = 2;
  assert(getA() == 2);
  assert(2 == getA2());
  assert(getA() == getA2());
  printf("%d %d", getA(), getA2());
  return 0;
}
