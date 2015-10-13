//
//  JBAzureMessage.m
//  PTAzureMessage
//
//  Created by Jay Baker on 6/10/15.
//  Copyright © 2015 Jay Baker. All rights reserved.
//

#import "JBAzureMessage.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>

@implementation JBAzureMessage

/**
 * SBNotificationHubHelper
 * https://github.com/Azure/azure-notificationhubs/blob/master/iOS/WindowsAzureMessaging/WindowsAzureMessaging/Helpers/SBNotificationHubHelper.m
 */
const int defaultTimeToExpireinMins = 20;
static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char decodingTable[128];

/**
 * SBTokenProvider
 * https://github.com/Azure/azure-notificationhubs/blob/master/iOS/WindowsAzureMessaging/WindowsAzureMessaging/Helpers/SBTokenProvider.m
 */
static NSString* decodingTableLock = @"decodingTableLock";
@synthesize timeToExpireinMins;

-(id)initWithEndPoint:(NSURL *)endpoint andKeyName:(NSString *)keyName andKeySecret:(NSString *)secret
{
    if (self = [super init]) {
        // [SBConnectionString stringWithEndpoint:(NSURL*)endpoint issuer:(NSString*) issuer issuerSecret:(NSString*)secret]
        if(!endpoint || !keyName || !secret)
        {
            NSLog(@"endpoint/keyName/secret can't be null.");
            return nil;
        }
        
        self->messageEndpoint = endpoint;
        self->messageKeyName = keyName;
        self->messageKeySecret = secret;
        
        // [SBNotificationHubHelper modifyEndpoint:(NSURL *)endPoint scheme:(NSString*)scheme]
        NSString *scheme = @"sb";
        NSString* modifiedEndpoint = [NSString stringWithString:[endpoint absoluteString]];
        
        if(![modifiedEndpoint hasSuffix:@"/"])
        {
            modifiedEndpoint = [NSString stringWithFormat:@"%@/",modifiedEndpoint];
        }
        
        NSInteger position = [modifiedEndpoint rangeOfString:@":"].location;
        if( position == NSNotFound)
        {
            modifiedEndpoint = [scheme stringByAppendingFormat:@"://%@",modifiedEndpoint];
        }
        else
        {
            modifiedEndpoint = [scheme stringByAppendingFormat:@"%@",[modifiedEndpoint substringFromIndex:position]];
        }
        
        endpoint = [NSURL URLWithString:modifiedEndpoint];
        
        // [SBConnectionString stringWithEndpoint:(NSURL*)endpoint issuer:(NSString*) issuer issuerSecret:(NSString*)secret]
        NSString* endpointUri = [endpoint absoluteString];
        if([[endpointUri lowercaseString] hasPrefix:@"endpoint="])
        {
            connectionString = [NSString stringWithFormat:@"%@;SharedAccessKeyName=%@;SharedAccessKey=%@",endpointUri,keyName,secret];
        }
        else
        {
            connectionString = [NSString stringWithFormat:@"Endpoint=%@;SharedAccessKeyName=%@;SharedAccessKey=%@",endpointUri,keyName,secret];
        }
        
        // [SBTokenProvider PrepareSharedAccessTokenWithUrl:(NSURL*)url]
        NSTimeInterval interval = [[NSDate date] timeIntervalSince1970];
        int totalSeconds = interval + self->timeToExpireinMins*60;
        NSString* expiresOn = [NSString stringWithFormat:@"%d", totalSeconds];
        
        NSString* audienceUri = [endpoint absoluteString];
        audienceUri = [[audienceUri lowercaseString] stringByReplacingOccurrencesOfString:@"https://" withString:@"http://"];
        audienceUri = [[self urlEncode:audienceUri] lowercaseString];
        
        NSString* signature = [self signString:[audienceUri stringByAppendingFormat:@"\n%@",expiresOn] withKey:secret];
        signature = [self urlEncode:signature];
        
        token = [NSString stringWithFormat:@"SharedAccessSignature sr=%@&sig=%@&se=%@&skn=%@", audienceUri, signature, expiresOn, keyName];
        
        NSLog(@"%@", token);
    }
    
    return self;
}

-(void)sendMessage:(NSData *)message
{
    [self sendMessage:message withCallback:nil];
}

-(void)sendMessage:(NSData *)message withCallback:(void(^)(BOOL))callback
{
    NSString *urlStr = [[NSURL URLWithString:[NSString stringWithFormat:@"%@/%@", [self->messageEndpoint absoluteString], @"messages"]] absoluteString];
    urlStr = [urlStr stringByReplacingOccurrencesOfString:@"sb://" withString:@"https://"];
    NSURL *url = [NSURL URLWithString:urlStr];
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    
    NSURLSessionConfiguration *sessionConifguration = [NSURLSessionConfiguration defaultSessionConfiguration];
    [sessionConifguration setHTTPAdditionalHeaders:@{
                                                     @"Authorization": self->token,
                                                     @"Content-Type": @"text/plain"
                                                     }];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConifguration];
    
    request.HTTPBody = message;
    request.HTTPMethod = @"POST";
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (error) {
            NSLog(@"Error: %@", error);
            callback(NO);
        } else {
            callback(YES);
        }
    }];
    
    [task resume];
}

-(void)recvMessage:(void(^)(id))callback
{
    NSString *urlStr = [[NSURL URLWithString:[NSString stringWithFormat:@"%@/%@", [self->messageEndpoint absoluteString], @"messages/head?timeout=60"]] absoluteString];
    urlStr = [urlStr stringByReplacingOccurrencesOfString:@"sb://" withString:@"https://"];
    NSURL *url = [NSURL URLWithString:urlStr];
    
    NSLog(@"%@", urlStr);
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    
    NSURLSessionConfiguration *sessionConifguration = [NSURLSessionConfiguration defaultSessionConfiguration];
    [sessionConifguration setHTTPAdditionalHeaders:@{
                                                     @"Authorization": self->token,
                                                     @"Content-Type": @"text/plain"
                                                     }];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConifguration];
    
    request.HTTPMethod = @"DELETE";
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (error) {
            NSLog(@"Error: %@", error);
            callback(nil);
        } else {
            callback(data);
        }
    }];
    
    [task resume];
}

/**
 * SBNotificationHubHelper
 * https://github.com/Azure/azure-notificationhubs/blob/master/iOS/WindowsAzureMessaging/WindowsAzureMessaging/Helpers/SBNotificationHubHelper.m
 */
- (NSString*) urlEncode: (NSString*)urlString{
    return (__bridge NSString*)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)urlString, NULL,CFSTR("!*'();:@&=+$,/?%#[]"),  kCFStringEncodingUTF8);
}

/**
 * SBNotificationHubHelper
 * https://github.com/Azure/azure-notificationhubs/blob/master/iOS/WindowsAzureMessaging/WindowsAzureMessaging/Helpers/SBNotificationHubHelper.m
 */
- (NSString*) urlDecode: (NSString*)urlString{
    return [[urlString
             stringByReplacingOccurrencesOfString:@"+" withString:@" "]
            stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
}

/**
 * SBNotificationHubHelper
 * https://github.com/Azure/azure-notificationhubs/blob/master/iOS/WindowsAzureMessaging/WindowsAzureMessaging/Helpers/SBNotificationHubHelper.m
 */
- (NSString*) signString: (NSString*)str withKeyData:(const char*) cKey keyLength:(NSInteger) keyLength{
    const char *cData = [str cStringUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA256, cKey, keyLength, cData, strlen(cData), cHMAC);
    
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:CC_SHA256_DIGEST_LENGTH];
    
    NSString* signature = [self toBase64:(unsigned char *)[HMAC bytes] length:[HMAC length]];
    
    return signature;
    
}

/**
 * SBNotificationHubHelper
 * https://github.com/Azure/azure-notificationhubs/blob/master/iOS/WindowsAzureMessaging/WindowsAzureMessaging/Helpers/SBNotificationHubHelper.m
 */
- (NSString*) signString: (NSString*)str withKey:(NSString*) key{
    const char *cKey = [key cStringUsingEncoding:NSASCIIStringEncoding];
    return [self signString:str withKeyData:cKey keyLength:strlen(cKey)];
}

/**
 * SBNotificationHubHelper
 * https://github.com/Azure/azure-notificationhubs/blob/master/iOS/WindowsAzureMessaging/WindowsAzureMessaging/Helpers/SBNotificationHubHelper.m
 */
- (NSData*) fromBase64: (NSString*) str{
    
    if(decodingTable['B'] != 1)
    {
        @synchronized(decodingTableLock)
        {
            if(decodingTable['B'] != 1)
            {
                memset(decodingTable, 0, 128);
                int length = (sizeof encodingTable);
                for (int i = 0; i < length; i++)
                {
                    decodingTable[encodingTable[i]] = i;
                }
            }
        }
    }
    
    NSData* inputData = [str dataUsingEncoding:NSASCIIStringEncoding];
    const char* input =inputData.bytes;
    NSInteger inputLength = inputData.length;
    
    if ((input == NULL) || (inputLength% 4 != 0)) {
        return nil;
    }
    
    while (inputLength > 0 && input[inputLength - 1] == '=') {
        inputLength--;
    }
    
    int outputLength = inputLength * 3 / 4;
    NSMutableData* outputData = [NSMutableData dataWithLength:outputLength];
    uint8_t* output = outputData.mutableBytes;
    
    int outputPos = 0;
    for (int i=0; i<inputLength; i += 4)
    {
        char i0 = input[i];
        char i1 = input[i+1];
        char i2 = i+2 < inputLength ? input[i+2] : 'A';
        char i3 = i+3 < inputLength ? input[i+3] : 'A';
        
        char result =(decodingTable[i0] << 2) | (decodingTable[i1] >> 4);
        output[outputPos++] =  result;
        if (outputPos < outputLength) {
            output[outputPos++] = ((decodingTable[i1] & 0xf) << 4) | (decodingTable[i2] >> 2);
        }
        if (outputPos < outputLength) {
            output[outputPos++] = ((decodingTable[i2] & 0x3) << 6) | decodingTable[i3];
        }
    }
    
    return outputData;
}

/**
 * SBNotificationHubHelper
 * https://github.com/Azure/azure-notificationhubs/blob/master/iOS/WindowsAzureMessaging/WindowsAzureMessaging/Helpers/SBNotificationHubHelper.m
 */
- (NSString*) toBase64: (unsigned char*) data length:(NSInteger) length{
    
    NSMutableString *dest = [[NSMutableString alloc] initWithString:@""];
    
    unsigned char * tempData = (unsigned char *)data;
    NSInteger srcLen = length;
    
    for (int i=0; i<srcLen; i += 3)
    {
        NSInteger value = 0;
        for (int j = i; j < (i + 3); j++) {
            value <<= 8;
            
            if (j < length) {
                value |= (0xFF & tempData[j]);
            }
        }
        
        [dest appendFormat:@"%c", encodingTable[(value >> 18) & 0x3F]];
        [dest appendFormat:@"%c", encodingTable[(value >> 12) & 0x3F]];
        [dest appendFormat:@"%c", (i + 1) < length ? encodingTable[(value >> 6)  & 0x3F] : '='];
        [dest appendFormat:@"%c", (i + 2) < length ? encodingTable[(value >> 0)  & 0x3F] : '='];
    }
    
    return dest;
}

@end
