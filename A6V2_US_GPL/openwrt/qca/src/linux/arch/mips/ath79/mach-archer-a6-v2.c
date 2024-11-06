
/*
 * Atheros AP152 reference board support
 *
 * Copyright (c) 2014 The Linux Foundation. All rights reserved.
 * Copyright (c) 2012 Gabor Juhos <juhosg@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <linux/platform_device.h>
#include <linux/ath9k_platform.h>
#include <linux/ar8216_platform.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>

#include <asm/mach-ath79/ar71xx_regs.h>

#include "common.h"
#include "dev-m25p80.h"
#include "machtypes.h"
#include "pci.h"
#include "dev-eth.h"
#include "dev-gpio-buttons.h"
#include "dev-leds-gpio.h"
#include "dev-usb.h"
#include "dev-spi.h"
#include "dev-wmac.h"


#define AP152_GPIO_LED_WLAN_2G          14
#define AP152_GPIO_LED_WLAN_5G          9
#define AP152_GPIO_LED_WPS              1
#define AP152_GPIO_LED_STATUS           6

#define AP152_GPIO_LED_WAN_INET         8
#define AP152_GPIO_LED_WAN_LINK         7
#define AP152_GPIO_LED_LAN             15




#define AP152_GPIO_BTN_RESET            5
#define AP152_GPIO_BTN_WPS_WIFI         2
#define AP152_KEYS_POLL_INTERVAL        20     /* msecs */
#define AP152_KEYS_DEBOUNCE_INTERVAL    (3 * AP152_KEYS_POLL_INTERVAL)

#define AP152_MAC0_OFFSET               0
#define AP152_MAC1_OFFSET               6
#define AP152_WMAC_CALDATA_OFFSET       0x1000

#define AP152_GPIO_MDC			3
#define AP152_GPIO_MDIO			4

extern void gpio_set_value(unsigned gpio, int value);


static struct gpio_led ap152_leds_gpio[] __initdata = {
	{
		.name		= "wifi_2g",
		.gpio		= AP152_GPIO_LED_WLAN_2G,
		.active_low	= 1,
	},
	{
		.name		= "wifi_5g",
		.gpio		= AP152_GPIO_LED_WLAN_5G,
		.active_low	= 1,
	},
	{
		.name		= "status",
		.gpio		= AP152_GPIO_LED_STATUS,
		.active_low	= 1,
		.default_state = LEDS_GPIO_DEFSTATE_ON,
	},
	{
		.name		= "lan",
		.gpio		= AP152_GPIO_LED_LAN,
		.active_low	= 1,
	},
	{
		.name		= "wan_link",
		.gpio		= AP152_GPIO_LED_WAN_LINK,
		.active_low	= 0,
	},
	{
		.name		= "wan_inet",
		.gpio		= AP152_GPIO_LED_WAN_INET,
		.active_low	= 0,
	},
	{
		.name		= "wps",
		.gpio		= AP152_GPIO_LED_WPS,
		.active_low	= 1,
	},
};

static struct gpio_keys_button ap152_gpio_keys[] __initdata = {
        {
                .desc           = "WPS and WIFI button",
                .type           = EV_KEY,
                .code           = KEY_WPS_BUTTON,
                .debounce_interval = AP152_KEYS_DEBOUNCE_INTERVAL,
                .gpio           = AP152_GPIO_BTN_WPS_WIFI,
                .active_low     = 1,
        },
        {
                .desc           = "Reset button",
                .type           = EV_KEY,
                .code           = KEY_RESTART,
                .debounce_interval = AP152_KEYS_DEBOUNCE_INTERVAL,
                .gpio           = AP152_GPIO_BTN_RESET,
                .active_low     = 1,
        },
};

static struct ar8327_pad_cfg ap152_ar8337_pad0_cfg = {
	.mode = AR8327_PAD_MAC_SGMII,
	.sgmii_txclk_phase_sel = AR8327_SGMII_CLK_PHASE_RISE,
	.sgmii_rxclk_phase_sel = AR8327_SGMII_CLK_PHASE_FALL,
};

static struct ar8327_platform_data ap152_ar8337_data = {
	.pad0_cfg = &ap152_ar8337_pad0_cfg,
	.cpuport_cfg = {
		.force_link = 1,
		.speed = AR8327_PORT_SPEED_1000,
		.duplex = 1,
		.txpause = 1,
		.rxpause = 1,
	},
};

static struct mdio_board_info ap152_mdio0_info[] = {
	{
		.bus_id = "ag71xx-mdio.0",
		.phy_addr = 0,
		.platform_data = &ap152_ar8337_data,
	},
};

static void __init ap152_mdio_setup(void)
{
	ath79_gpio_output_select(AP152_GPIO_MDC, QCA956X_GPIO_OUT_MUX_GE0_MDC);
	ath79_gpio_output_select(AP152_GPIO_MDIO, QCA956X_GPIO_OUT_MUX_GE0_MDO);

	ath79_register_mdio(0, 0x0);
}

static void __init archer_a6v2_setup(void)
{
	u8 *art = (u8 *) KSEG1ADDR(0x1fff0000);

	ath79_register_m25p80(NULL);

	ath79_register_leds_gpio(-1, ARRAY_SIZE(ap152_leds_gpio),
							ap152_leds_gpio);
	ath79_register_gpio_keys_polled(-1, AP152_KEYS_POLL_INTERVAL,
									ARRAY_SIZE(ap152_gpio_keys),
									ap152_gpio_keys);

	/*disable usb in system booting period*/

        ap152_mdio_setup();

	mdiobus_register_board_info(ap152_mdio0_info,
								ARRAY_SIZE(ap152_mdio0_info));

	ath79_register_wmac(art + AP152_WMAC_CALDATA_OFFSET, NULL);
	ath79_register_pci();

	/* GMAC0 is connected to an AR8337 switch */
	ath79_init_mac(ath79_eth0_data.mac_addr, art + AP152_MAC0_OFFSET, 0);
	ath79_eth0_data.phy_if_mode = PHY_INTERFACE_MODE_SGMII;
	ath79_eth0_data.speed = SPEED_1000;
	ath79_eth0_data.duplex = DUPLEX_FULL;
	ath79_eth0_data.phy_mask = BIT(0);
	ath79_eth0_data.force_link = 1;
	ath79_eth0_data.mii_bus_dev = &ath79_mdio0_device.dev;
	ath79_eth0_pll_data.pll_1000 = 0x06000000;
	ath79_register_eth(0);
}

MIPS_MACHINE(ATH79_MACH_ARCHER_A6_V2, "AP152", "TP-LINK Archer A6 v2 support",
	     archer_a6v2_setup);
