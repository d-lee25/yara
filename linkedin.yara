rule Linkedin {
 strings: 
        $linkedIn1 = /http(s)?:\/\/([\w]+\.)?linkedin\.com\/in\/[A-z0-9\%_-]+\/?/ ascii wide
        $linkedIn2 = /http(s)?:\/\/([\w]+\.)?linkedin\.com\/pub\/[A-z 0-9_-]+(\/[A-z0-9]+){3}\/?/ ascii wide

 condition: $linkedIn1 or $linkedIn2
}
