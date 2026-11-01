#include <stdlib.h>
#include <stdio.h>
#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void) {
  printf("Setting up tests...\n");
}

void tearDown(void) {
  printf("Tearing down tests...\n");
}

void test_ip_parse_reject(void)
{
  uint32_t addr;
  TEST_ASSERT_FALSE(ip_parse("1.2.3", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4.5", &addr));
  TEST_ASSERT_FALSE(ip_parse("1..2.3", &addr));
  TEST_ASSERT_FALSE(ip_parse("256.1.1.1", &addr));
  TEST_ASSERT_FALSE(ip_parse("010.0.0.1", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4x", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4/33", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4/024", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4/", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3/24", &addr));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_reject);
  return UNITY_END();
}
