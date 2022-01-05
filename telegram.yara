rule Telegram {
    strings: 
        $telegram = /https?:\/\/(t(elegram)?\.me|telegram\.org)\/([a-z0-9\_]{5,32})\/?/ ascii wide

    condition: 1 of them
}
