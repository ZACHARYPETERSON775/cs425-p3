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

void test_cidr_arithmetic(void)
{
  cidr_t block = { UINT32_C(0x84b2e30b), 25 };

  TEST_ASSERT_EQUAL_HEX32(0, cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xffffff80), cidr_mask(25));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(33));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e300), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e37f), cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e301), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e37e), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(126, cidr_host_count(block));
  TEST_ASSERT_TRUE(cidr_contains(block, UINT32_C(0x84b2e332)));
  TEST_ASSERT_FALSE(cidr_contains(block, UINT32_C(0x84b2e3c8)));
  TEST_ASSERT_FALSE(cidr_is_network(block));
  block.addr = UINT32_C(0x84b2e300);
  TEST_ASSERT_TRUE(cidr_is_network(block));

  block.addr = UINT32_C(0x12345678);
  block.prefix = 0;
  TEST_ASSERT_EQUAL_HEX32(0, cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(1, cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xfffffffe), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(block));

  block.addr = UINT32_C(0xc0a8010b);
  block.prefix = 31;
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010b), cidr_broadcast(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010a), cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a8010b), cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(block));

  block.prefix = 32;
  TEST_ASSERT_EQUAL_HEX32(block.addr, cidr_first_host(block));
  TEST_ASSERT_EQUAL_HEX32(block.addr, cidr_last_host(block));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(block));
}

void test_cidr_subnet(void)
{
  cidr_t block = { UINT32_C(0xc0a80100), 24 };
  cidr_t subnet = { UINT32_C(0x12345678), 12 };

  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xc0a801c0), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(26, subnet.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 1, 0, &subnet));
  TEST_ASSERT_EQUAL_HEX32(block.addr, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(block.prefix, subnet.prefix);

  cidr_t original = subnet;
  TEST_ASSERT_FALSE(cidr_subnet(block, 0, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 3, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 4, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 512, 0, &subnet));
  TEST_ASSERT_FALSE(cidr_subnet(block, 1, 0, NULL));
  TEST_ASSERT_EQUAL_HEX32(original.addr, subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(original.prefix, subnet.prefix);

  block.addr++;
  TEST_ASSERT_FALSE(cidr_subnet(block, 1, 0, &subnet));

  block.addr = 0;
  block.prefix = 0;
  TEST_ASSERT_TRUE(cidr_subnet(block, UINT32_C(0x80000000),
                               UINT32_C(0x7fffffff), &subnet));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xfffffffe), subnet.addr);
  TEST_ASSERT_EQUAL_UINT8(31, subnet.prefix);
}

void test_route_parse(void)
{
  route_t route = { { UINT32_C(0x12345678), 12 }, UINT32_C(0xabcdef01), "old" };

  TEST_ASSERT_TRUE(route_parse("default 132.178.227.1 eno1\n", &route));
  TEST_ASSERT_EQUAL_HEX32(0, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84b2e301), route.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", route.dev);

  TEST_ASSERT_TRUE(route_parse("10.1.0.0/16 direct eth1", &route));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0a010000), route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(16, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(0, route.gateway);
  TEST_ASSERT_EQUAL_STRING("eth1", route.dev);

  route_t original = route;
  TEST_ASSERT_FALSE(route_parse("10.1.0.1/16 direct eth1", &route));
  TEST_ASSERT_FALSE(route_parse("10.1.0.0/16 010.0.0.1 eth1", &route));
  TEST_ASSERT_FALSE(route_parse("10.1.0.0/16 direct", &route));
  TEST_ASSERT_FALSE(route_parse("10.1.0.0/16 direct eth1 extra", &route));
  TEST_ASSERT_FALSE(route_parse("10.1.0.0/16 direct interface-name-too-long", &route));
  TEST_ASSERT_FALSE(route_parse(NULL, &route));
  TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));
  TEST_ASSERT_EQUAL_HEX32(original.dest.addr, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(original.dest.prefix, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(original.gateway, route.gateway);
  TEST_ASSERT_EQUAL_STRING(original.dev, route.dev);
}

void test_forwarding_table(void)
{
  fwd_table_t *table = table_create();
  TEST_ASSERT_TRUE(table != NULL);
  TEST_ASSERT_EQUAL_size_t(0, table_count(table));
  TEST_ASSERT_EQUAL_size_t(0, table_count(NULL));
  TEST_ASSERT_NULL(table_lookup(NULL, UINT32_C(0x0a0102c8)));

  FILE *input = tmpfile();
  TEST_ASSERT_TRUE(input != NULL);
  fputs("# example routes\n"
        "10.1.2.128/25 10.1.2.1 eth2 # router behind eth2\n"
        "default 132.178.227.1 eno1\n"
        "132.178.227.0/25 direct eno1\n"
        "10.0.0.0/8 10.1.0.1 eth1\n"
        "10.1.2.0/24 direct eth2\n"
        "10.1.0.0/16 direct eth1\n"
        "192.168.0.0/16 10.1.0.1 eth1\n", input);
  rewind(input);

  size_t bad_line = 99;
  TEST_ASSERT_TRUE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_size_t(0, bad_line);
  TEST_ASSERT_EQUAL_size_t(7, table_count(table));
  fclose(input);

  const route_t *match = table_lookup(table, UINT32_C(0x0a0102c8));
  TEST_ASSERT_TRUE(match != NULL);
  TEST_ASSERT_EQUAL_UINT8(25, match->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("eth2", match->dev);

  match = table_lookup(table, UINT32_C(0x0a010250));
  TEST_ASSERT_TRUE(match != NULL);
  TEST_ASSERT_EQUAL_UINT8(24, match->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("eth2", match->dev);

  match = table_lookup(table, UINT32_C(0x0a010350));
  TEST_ASSERT_TRUE(match != NULL);
  TEST_ASSERT_EQUAL_UINT8(16, match->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("eth1", match->dev);

  match = table_lookup(table, UINT32_C(0xc0a80101));
  TEST_ASSERT_TRUE(match != NULL);
  TEST_ASSERT_EQUAL_UINT8(16, match->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("eth1", match->dev);

  match = table_lookup(table, UINT32_C(0x08080808));
  TEST_ASSERT_TRUE(match != NULL);
  TEST_ASSERT_EQUAL_UINT8(0, match->dest.prefix);
  TEST_ASSERT_EQUAL_STRING("eno1", match->dev);

  route_t duplicate = { { UINT32_C(0x0a010000), 16 }, 0, "eth9" };
  TEST_ASSERT_FALSE(table_add(table, &duplicate));
  TEST_ASSERT_FALSE(table_add(NULL, &duplicate));
  TEST_ASSERT_FALSE(table_add(table, NULL));
  TEST_ASSERT_EQUAL_size_t(7, table_count(table));

  input = tmpfile();
  TEST_ASSERT_TRUE(input != NULL);
  fputs("192.0.2.0/24 direct eth0\n"
        "192.0.2.0/24 192.0.2.1 eth1\n", input);
  rewind(input);
  TEST_ASSERT_FALSE(table_load(table, input, &bad_line));
  TEST_ASSERT_EQUAL_size_t(2, bad_line);
  TEST_ASSERT_EQUAL_size_t(8, table_count(table));
  fclose(input);

  table_destroy(table);
  table_destroy(NULL);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_reject);
  RUN_TEST(test_ip_parse_and_format);
  RUN_TEST(test_cidr_parse_reject);
  RUN_TEST(test_cidr_parse_and_format);
  RUN_TEST(test_cidr_arithmetic);
  RUN_TEST(test_cidr_subnet);
  RUN_TEST(test_route_parse);
  RUN_TEST(test_forwarding_table);
  return UNITY_END();
}
