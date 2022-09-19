rule Fasta {
    strings:
        //$dna_line = /[autgcn]{70,}/ nocase
        $fasta1 = /((^|\n|\r)>.*)((\r|\n)([autgcn]{5,}.*(\n|\r|[\r\n])){7,10})/ nocase
     
    condition: 1 of them
}
rule Fastq {
    strings:
        $fastq = /(^|\n|\r)\@.*((\r\n|[\r\n])([autgcn]{10,}))+[\r\n](\+.*)/ nocase
    
    condition: 1 of them
}
rule Genbank {
    strings:
        $genbank1 = /(ORIGIN[\t ].*)/ nocase
        $genbank2 = /([\t ] \d+ ([autgcn].*)(\r|\n|[\t ]))/ nocase
        
    condition:
        //($genbank1) and (#genbank2 > 200) //is there a typical size (min) for genbank2 in this type of file ? 
        all of them
}
rule Clustal {
    strings:
        $clustal1 = /^(CLUSTAL|PROBCONS|MUSCLE|MSAPROBS|Kalign).*/ nocase
        $clustal4 = /(^|\n|\r)(gi).*(\r\n|[\r\n])((gi).*(\r\n|[\r\n]))+/ nocase

    condition:
        all of them
}
rule Embl {
    strings:
        $embl1 = /SQ[ \t]*.*;[\t ]*/
        $embl2 = /([\t ]([ \t]+[autgcn]+)+[\t ]+\d+)/ //(\r\n|[\r\n]))+/
    condition:
        all of them
        // might be able to adjust and concatenate with post processor
}

rule PHD {
    strings:
        $phd1 = /(^)BEGIN_SEQUENCE.*/
        $phd2 = /BEGIN_COMMENT/
        $phd3 = /END_COMMENT[\t ]*/
        $phd4 = /BEGIN_DNA[\t ]*/
        $phd5 = /END_DNA.*/
        $phd6 = /END_SEQUENCE/
    condition:
        all of them
}
rule Phylip {
    strings:
         $phylip1 = /^[ \t]+\d+[ \t]+\d+[\t ]*[\n]/ nocase
         //$phylip2 = /([a-km-zA-HJ-NP-Z1-9]{10,}.*)/ nocase 
         $phylip3 = /[autgcn]{10,}/ nocase
    condition:
        all of them
}
rule Stockholm {
    strings:
        $stockholm1 = /^# STOCKHOLM .*/ 
        $stockholm2 = /([autgcn-]{10,})/ nocase
   condition:
       all of them
}
rule XML {
    strings:
        $seqXML = /<\/seqXML>/

    condition:
        any of them
}


