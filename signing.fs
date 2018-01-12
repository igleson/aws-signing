[<CompiledName("ToHexDigit")>]
    let toHexDigit n =
        if n < 10 then char (n + 0x30) else char (n + 0x37)
        
    [<CompiledName("Encode")>]
    let hexEncode (buf:byte array) =
        let hex = Array.zeroCreate (buf.Length * 2)
        let mutable n = 0
        for i = 0 to buf.Length - 1 do
            hex.[n] <- toHexDigit ((int buf.[i] &&& 0xF0) >>> 4)
            n <- n + 1
            hex.[n] <- toHexDigit (int buf.[i] &&& 0xF)
            n <- n + 1
        new String(hex)
        
    let shaPovider = new SHA256CryptoServiceProvider()
    
    //FIXME use StringBuilder
    let toSHA256 (v: byte array) = (v |> shaPovider.ComputeHash |> BitConverter.ToString).Replace("-", "").ToLower()

    [<Literal>]
    let HMACAlgorithm = "HMACSHA256"
    
    /// The length of the HMAC value in number of bytes
    [<Literal>]
    let HMACLength = 32 // = 256 / 8
    
    let hmacCreate = HMAC.Create(HMACAlgorithm)
    
    /// Calculate the HMAC of the passed data given a private key
    let hmac (key : byte []) offset count (data : byte[]) =
        hmacCreate.Key <- key
        hmacCreate.ComputeHash (data, offset, count)
    
    let toHMAC (data : byte []) key = 
        use hmacsha = new HMACSHA256(key)
        hmacsha.ComputeHash data
        
        
        
        
        
        
        let hash (content : HttpContent) = 
    content
    |> Option.ofObj
    |> Option.map (fun c -> c.ReadAsByteArrayAsync() |> Async.AwaitTask)
    |> Option.defaultValue (async{return [||]})
    |> Async.RunSynchronously
    |> Utils.toSHA256

let signRequest (dateNow : DateTime) accessKey secretKey (request : HttpRequestMessage) = 
    let canonicalQuery = request.RequestUri.Query.Replace("?", "")
    
    let headers = 
        request.Content
        |> Option.ofObj
        |> Option.map (fun x -> x.Headers |> seq)
        |> Option.defaultValue Seq.empty
        |> Seq.append (request.Headers |> seq)
        |> Seq.sortBy (fun h -> h.Key.ToLowerInvariant())
    
    let canonicalHeaders = 
        headers
        |> Seq.map (fun k -> sprintf "%s:%s\n" (k.Key.ToLowerInvariant()) (k.Value.First().Trim()))
        |> Seq.reduce (+)
    
    let signedHeaders = 
        headers
        |> Seq.map (fun kv -> kv.Key.ToLowerInvariant())
        |> Seq.reduce (sprintf "%s;%s")
    
    let hexEncode = (request.Content |> hash)
    let CanonicalRequest = 
        (sprintf "%s\n%s\n%s\n%s\n%s\n%s" (request.Method.ToString()) request.RequestUri.AbsolutePath canonicalQuery canonicalHeaders signedHeaders 
             hexEncode)
    
    let hashedCanonicalRequest = 
        CanonicalRequest
        |> Encoding.UTF8.GetBytes
        |> toSHA256

    let service = "kinesis"
    let fullDate = dateNow.ToString("yyyyMMddTHHmmssZ")
    let partialDate = dateNow.ToString("yyyyMMdd")
    let credentialScope = sprintf "%s/us-east-1/%s/aws4_request" partialDate service
    let stringToSignStr = sprintf "AWS4-HMAC-SHA256\n%s\n%s\n%s" fullDate credentialScope hashedCanonicalRequest
    let stringToSign = stringToSignStr |> Encoding.UTF8.GetBytes
    let key = "AWS4" + secretKey |> Encoding.UTF8.GetBytes
    let date_ = partialDate |> Encoding.UTF8.GetBytes
    let region = "us-east-1" |> Encoding.UTF8.GetBytes

    let service_ = service |> Encoding.UTF8.GetBytes
    let aws4Request = "aws4_request" |> Encoding.UTF8.GetBytes
    
    let signature = 
        (key
         |> toHMAC date_
         |> toHMAC region
         |> toHMAC service_
         |> toHMAC aws4Request
         |> toHMAC stringToSign
         |> BitConverter.ToString).Replace("-", "").ToLower()
    sprintf "Credential=%s/%s/us-east-1/%s/aws4_request, SignedHeaders=%s, Signature=%s" accessKey partialDate service signedHeaders signature
