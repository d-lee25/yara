rule Youtube {
    strings: 
        $youtube = /(http:\/\/)?(www\.)?(youtube|yimg|youtu)\.([A-Za-z]{2,4}|[A-Za-z]{2}\.[A-Za-z]{2})\/(watch\?v=)?[A-Za-z0-9\-_]{6,12}(&[A-Za-z0-9\-_]{1,}=[A-Za-z0-9\-_]{1,})*/ ascii wide

    condition: 1 of them
}
