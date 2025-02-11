# UMAS-Wireshark-Dissector
[](https://github.com/zaltzman/UMAS-Wireshark-Dissector#umas-wireshark-dissector)

An improved Wireshark Lua dissector for Schneider Electric Modicon PLCs UMAS protocol  (originally created by [biero-el-corridor](https://github.com/biero-el-corridor/Wireshark-UMAS-Modicon-M340-protocol)) with the following key improvements:

* Added detection for more UMAS functions, along with their descriptions.
* Added support for correctly parsing reserved signed messages (both request and response messages).
* Added a 'Request_Function_Code' field to relate each response message to its corresponding request message for easier analysis and packet filtering.

This dissector is based on the research "[From Pass-the-Hash to Code Execution on Schneider Electric M340 PLCs](https://www.blackhat.com/eu-24/briefings/schedule/#from-pass-the-hash-to-code-execution-on-schneider-electric-m340-plcs-42573)" presented at Black Hat Europe 2024.

**General UMAS message structure:**

![UMAS_structure](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas1.png) 

## Usage

Add the [Lua script](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/umas-wireshark-dissector.lua) file to Wireshark default plugins folder:
*Windows:*
```sh
C:\Program Files\Wireshark\plugins\
```
*Linux:*
```sh
/usr/lib/wireshark/plugins/
```
*macOS:*
```sh
/Applications/Wireshark.app/Contents/Resources/lib/wireshark/plugins/
```

## Added UMAS function codes
The following UMAS functions have been added to the original dissector:
|  UMAS function code              |Name                          |Description               |
|----------------|-------------------------------|-----------------------------|
|0x05|`READ_LOADER_INFO`|Get loader Info|
|0x07|`READ_BLOCK_INFO`|Get block Info|
|0x21|`WRITE_MEMORY_BLOCK`|Write a memory block of the PLC|
|0x26|`DATA_DICTIONARY`|Data dictionary|
|0x27|`DATA_DICTIONARY_PRELOAD`|Data dictionary preload|
|0x28|`READ_PHYSICAL_ADDRESS`|Read from a physical address|
|0x29|`WRITE_PHYSICAL_ADDRESS`|Write to a physical address|
|0x2A|`BROWSE_EVENTS`|Browse events|
|0x36|`UMAS_BACKUP`|UMAS backup operations|
|0x37|`PRELOAD_BLOCKS`|Preload blocks|
|0x42|`INIT_PLC`|Initiates the PLC|
|0x43|`SWAP`|Swap blocks|
|0x51|`GET_AUTO_MODIF`|Get auto modifications|
|0x52|`GET_FORCED_BITS`|Get forced bits|
|0x53|`GET_SELECTED_BLOCKS`|Get selected blocks|
|0x60|`BKPT_SET`|Set a breakpoint|
|0x61|`BKPT_DEL`|Delete or reset a breakpoint|
|0x62|`STEP_OVER`|Steps over|
|0x63|`STEP_IN`|Steps in|
|0x64|`STEP_OUT`|Steps out|
|0x65|`GET_CALL_STACK`|Get call stack|
|0x66|`CHECK_DEBUG_ALLOWED`|Checks if debug is allowed|
|0x6C|`PROCESS_MSG`|Special process message mode|
|0x6D|`PRIVATE`|Private message operations|
|0x6E|`RESERVATION_NONCES`|Reservation nonces exchange|
|0x72|`READ_RACK`|Read rack info|
|0x74|`READ_DEVICE_DATA`|Read device data|

## Parsing the UMAS messages
The UMAS messages are transmitted over the MODBUS/TCP protocol and therefore share the MODBUS standard header.

There are two types of UMAS messages: public and reserved messages.

### UMAS public messages
UMAS public messages are the default messages exchanged between the engineering station and the PLC. They do not include any authentication components.

#### Request public message structure
![UMAS_public_request_structure](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas2.png)
Example:
![UMAS_public_request_example](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas6.png)
#### Respone public message structure
![UMAS_public_response_structure](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas3.png)
Example:
![UMAS_public_response_example](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas7.png)
### UMAS reserved messages
UMAS reserved messages are privileged messages exchanged after the authentication process between the engineering station and the PLC. The latest UMAS protocol includes cryptographic **signature** in these messages (a feature not handled in the original dissector).
#### Request reserved message structure
![UMAS_reserved_request_structure](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas4.png)
Example:
![UMAS_reserved_request_example](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas8.png)
#### Respone reserved message structure
![UMAS_reserved_response_structure](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas5.png)
Example:
![UMAS_reserved_response_example](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas9.png)
## Associating and filtering response messages by their related request messages
Added a field named 'Request_Function_Code' to response messages (both public and reserved), which stores the UMAS function code of the corresponding request message (based on the transaction ID). This makes it more convenient to determine which UMAS function a response belongs to and allows filtering based on responses to specific UMAS function requests.
### Associating example
Request message (UMAS_Function_Code=0x58, Transaction_Identity=876):
![UMAS_public_request_example](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas10.png)
Response message (Transaction_Identity=876):
![UMAS_public_response_example](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas11.png)
### Filtering example
Filtering response messages associated with UMAS function 0x50 request messages:
![UMAS_public_responses_filtering_example](https://raw.githubusercontent.com/zaltzman/UMAS-Wireshark-Dissector/refs/heads/main/Images/umas12.png)
## References
"From Pass-the-Hash to Code Execution on Schneider Electric M340 PLCs":
[Presentation slides](https://i.blackhat.com/EU-24/Presentations/EU-24-Zaltzman-From-Pass-the-Hash-to-Code-Execution.pdf)

[White paper](https://i.blackhat.com/EU-24/Presentations/EU-24-Zaltzman-From-Pass-the-Hash-to-Code-Execution-wp.pdf)