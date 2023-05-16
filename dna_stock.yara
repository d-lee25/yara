rule Stockholm {
    strings:
        $stockholm1 = /^# STOCKHOLM .*/ 
        $stockholm2 = /(\r\n|[\r\n]).*([autgcn-]{10,})(\r\n|[\r\n])/ 
   condition:
       all of them
}