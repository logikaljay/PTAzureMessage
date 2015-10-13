//
//  JBAzureMessage.h
//  PTAzureMessage
//
//  Created by Jay Baker on 6/10/15.
//  Copyright © 2015 Jay Baker. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface JBAzureMessage : NSObject
{
    NSString *connectionString;
    NSString *token;
    NSURL *messageEndpoint;
    NSString *messageKeyName;
    NSString *messageKeySecret;
}

@property (nonatomic) NSInteger timeToExpireinMins;

-(id)initWithEndPoint:(NSURL *)endpoint andKeyName:(NSString *)keyName andKeySecret:(NSString *)secret;


-(void)sendMessage:(NSData *)message;
-(void)sendMessage:(NSData *)message withCallback:(void(^)(BOOL))callback;
-(void)recvMessage:(void(^)(id))callback;

@end
