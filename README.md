# tcpsercli.py

78780D010865080044015069003A53F20D0A

78782E17180217121736CD021EF55504B49FE30058DA0000000000000000460637018B05D10000094A000029EA002620540D0A

78780A1346062B0F02020233D00D0A

78783116180217132E10C9021EF4EC04B49FF10019110900000000000000005006310202018B0000000009EC00003D40023070B10D0A

787811800B00000000434C4541524423000176D60D0A

I need to fix this code ill send next so it can decode 5 different hexes datas but currently it can only read one!
the requirements is that for the second one i want it to have is have just like the first one, a start bit 2 byte, a packet length 1 byte, protocol number 1 byte, a group called GPS information, inside of it a date time of 6 bytes, a quantity of gps satellites of 1 byte, a latitude of 4 bytes, a longitude of 4 bytes, a speed of 1 byte and a course, status of 2 bytes. Then another group called LBS information where inside theres a MCC of 2 bytes, MNC de 1 byte, um LAC de 2 bytes e um Cell ID de 3 bytes. e por ultimo o terceiro grupo chamado Status Information onde tem Device information de 1 byte, a battery voltage level of 1 byte, a gsm signal strength of 1 byte, a 2 byte battery voltage and a 2 byte external voltage. then out of the groups we have a 4 byte mileage, a 4 byte hourmeter, a information serial number of 2 bytes, a error check of 2 bytes and a end bit of 2 bytes.

the third one has a 2 byte start bit, a 1 byte packet length, a 1 byte protocol number, a group called status information with 1 byte device information, a 1 byte battery voltage level, a 1 byte GSM signal strength, a 1 byte external voltage, a 1 byte language byte which if theres a 01 its says chinese and if it says 02 its english. outside of it theres a 2 byte information serial number, a 2 byte error check and a 2 byte end bit

the fourth one also starts a 2 byte start bit, a 1 byte packet length and a 1 byte protocol number. then the same gps information, lbs information and status information just like the second one, but add the language one inside of status information. outside of the groups theres a 4 byte mileage, a 4 byte hourmeter, a 2 byte information serial number, a 2 byte error check, a 2 byte end bit

the last one and fifth one is a 2 byte start bit, packet length of 1 byte, a 1 byte protocol number, a 1 byte length of command, a 4 byte server flag bit, a M byte command content, a 2 byte serial number, a 2 byte error check and a 2 byte end bit.

now that ive mentioned all of it i'll send the code i made
