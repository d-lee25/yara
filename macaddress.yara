rule Mac_Address { 
    strings: 
        $mac_address_linux = /([\da-fA-F]{2}[:]){5}[\da-fA-F]{2}/ ascii wide
        $mac_address_win = /([\da-fA-F]{2}[-]){5}[\da-fA-F]{2}/ ascii wide
        $mac_address_cisco = /([\da-fA-F]{2}[\.]){5}[\da-fA-F]{2}/ ascii wide
    condition: 1 of them
}