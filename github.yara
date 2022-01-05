rule Github {
 strings: 
        $github1 = /http(s)?:\/\/(www\.)?github\.com\/[A-z0-9_-]{8,}\/?/ ascii wide
        $github2 = /http(s)?:\/\/([A-z0-9-_]+)\.github\.(com|io)\/?/ ascii wide

 condition: $github1 or $github2
}
