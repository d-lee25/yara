rule Skype {
    strings: 
        $skype = /(((callto|skype):)([a-z][a-z0-9\.,\-_]{5,31}))(\?(add|call|chat|sendfile|userinfo)){0,1}/ nocase ascii wide

    condition: 1 of them
}
