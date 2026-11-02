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
  uint32_t addr = UINT32_C(0x12345678);
  TEST_ASSERT_FALSE(ip_parse("1.2.3", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4.5", &addr));
  TEST_ASSERT_FALSE(ip_parse("1..2.3", &addr));
  TEST_ASSERT_FALSE(ip_parse("256.1.1.1", &addr));
  TEST_ASSERT_FALSE(ip_parse("010.0.0.1", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4x", &addr));
  TEST_ASSERT_FALSE(ip_parse("+1.2.3.4", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4junk", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4/33", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4/024", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4/", &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3/24", &addr));
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), addr);
}

void test_ip_parse_and_format(void)
{
  uint32_t addr = 0;
  char formatted[IP_STR_LEN];

  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), addr);
  ip_format(addr, formatted);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", formatted);

  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &addr));
  TEST_ASSERT_EQUAL_HEX32(0, addr);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, addr);
}

void test_cidr_parse_reject(void)
{
  cidr_t block = { UINT32_C(0x12345678), 12 };

  TEST_ASSERT_FALSE(cidr_parse("1.2.3", &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4.5/24", &block));
  TEST_ASSERT_FALSE(cidr_parse("1..2.3.4/24", &block));
  TEST_ASSERT_FALSE(cidr_parse("256.1.1.1/24", &block));
  TEST_ASSERT_FALSE(cidr_parse("010.0.0.1/24", &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4x/24", &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/33", &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/024", &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/", &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3/24", &block));
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x12345678), block.addr);
  TEST_ASSERT_EQUAL_UINT8(12, block.prefix);
}

void test_cidr_parse_and_format(void)
{
  cidr_t block = { 0, 0 };
  char formatted[CIDR_STR_LEN];

  TEST_ASSERT_TRUE(cidr_parse("192.168.1.10/24", &block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), block.addr);
  TEST_ASSERT_EQUAL_UINT8(24, block.prefix);
  cidr_format(block, formatted);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10/24", formatted);

  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT8(0, block.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &block));
  TEST_ASSERT_EQUAL_UINT8(32, block.prefix);

  block.prefix = 33;
  cidr_format(block, formatted);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", formatted);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_reject);
  RUN_TEST(test_ip_parse_and_format);
  RUN_TEST(test_cidr_parse_reject);
  RUN_TEST(test_cidr_parse_and_format);
  return UNITY_END();
}
