ecc508
=====

An OTP library for communicating with the [Microchip
ATECC608A](http://ww1.microchip.com/downloads/en/DeviceDoc/20005927A.pdf)
family of crypto-authentication devices.

Build
-----

    $ make

Use
---

You will need an ECC608A attached to an I2C bus on a board that has
I2C enabled, and can run Erlang.

For our most common use we wire up an ECC608A to a Raspberry Pi
configured for development and enable I2C using `raspi-config`.


Also install the Erlang development tools:

    $ sudo apt update
    $ sudo apst install erlang-nox erlang-dev i2c-tools

Once you've set up your Raspberry Pi and wired up the ECC608A you
should be able to see it using `i2cdetect`

    $ i2cdetect -y 1
    0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    00:          -- -- -- -- -- -- -- -- -- -- -- -- --
    10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
    20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
    30: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
    40: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
    50: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
    60: 60 -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
    70: -- -- -- -- -- -- -- --

This shows the ECC at address (hex) 60 on bus `i2c-1`.

For development purposes you can then clone this repository, and start
an Erlang shell to communicate with the ecc:

    $ git clone http://github.com/helium/ecc508
    $ cd ecc508
    $ ./rebar3 shell
    $ {ok, Pid} = ecc508:start_link().

Then check out the data-sheet linked above and the functions in the
eec508 module to see how to access the various functions of the
ECC608.
