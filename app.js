import AmazonCognitoIdentity from 'amazon-cognito-identity-js';
const CognitoUserPool = AmazonCognitoIdentity.CognitoUserPool;
import AWS from 'aws-sdk';
import request from 'request';
import jwkToPem from 'jwk-to-pem';
import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';

global.fetch = fetch;

const poolData = {    
UserPoolId : "eu-north-1_jZbSfQVMj", // Your user pool id here    
ClientId : "1lapf7ldj7nnetdfsl3ditjik7" // Your client id here
}; 
const pool_region = 'eu-north-1';

const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);


function RegisterUser(){
     var attributeList = [];
          attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"name",Value:"Neeraj Singh"}));
      attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"gender",Value:"male"}));
     attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"email",Value:"neeraj.singh+1@dimiour.io"}));
      attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({Name:"phone_number",Value:"+919517716629"}));

    userPool.signUp('neeraj_singh1', '12345@As', attributeList, null, function(err, result){
        if (err) {
            console.log("here")
            console.log(err);
            return;
        }
        let cognitoUser = result.user;
        console.log('user name is ' + cognitoUser.getUsername());
    });
}

function Login() {
    var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
        Username : 'neeraj_singh',
        Password : '12345@As1',
    });

    var userData = {
        Username : 'neeraj_singh',
        Pool : userPool
    };
    var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
            console.log('access token + ' + result.getAccessToken().getJwtToken());
            console.log('id token + ' + result.getIdToken().getJwtToken());
            console.log('refresh token + ' + result.getRefreshToken().getToken());
        },
        onFailure: function(err) {
            console.log(err);
        },

    });
}

async function  update(username, password){
       
     
  
        var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
            Username: username,
            Password: password,
        });

        var userData = {
            Username: username,
            Pool: userPool
        };
        var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
        await new Promise(res => cognitoUser.getSession(res));
        var attributeList = [];
        attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({
            Name: "name",
            Value: "Neeraj Ganesh Singh"
        }));

        cognitoUser.authenticateUser(authenticationDetails, {
            onSuccess: function (result) {
                cognitoUser.updateAttributes(attributeList, (err, result) => {
                    if (err) {
                        console.log(err)
                    } else {
                        console.log(result);
                    }
                });
            },
    
            onFailure: function(err) {
                console.log("Here",err);
            },
    
         });
    
       
}



function ValidateToken(token) {
        request({
            url: `https://cognito-idp.${pool_region}.amazonaws.com/${poolData.UserPoolId}/.well-known/jwks.json`,
            json: true
        }, function (error, response, body) {
            if (!error && response.statusCode === 200) {
                let pems = {};
                var keys = body['keys'];
                for(var i = 0; i < keys.length; i++) {
                    //Convert each key to PEM
                    var key_id = keys[i].kid;
                    var modulus = keys[i].n;
                    var exponent = keys[i].e;
                    var key_type = keys[i].kty;
                    var jwk = { kty: key_type, n: modulus, e: exponent};
                    var pem = jwkToPem(jwk);
                    pems[key_id] = pem;
                }
                //validate the token
                var decodedJwt = jwt.decode(token, {complete: true});
                if (!decodedJwt) {
                    console.log("Not a valid JWT token");
                    return;
                }

                var kid = decodedJwt.header.kid;
                var pem = pems[kid];
                if (!pem) {
                    console.log('Invalid token');
                    return;
                }

                jwt.verify(token, pem, function(err, payload) {
                    if(err) {
                        console.log("Invalid Token.");
                    } else {
                        console.log("Valid Token.");
                        console.log(payload);
                    }
                });
            } else {
                console.log(error)
                console.log("Error! Unable to download JWKs");
            }
        });
}


function renew(refresh_token) {
    const RefreshToken = new AmazonCognitoIdentity.CognitoRefreshToken({RefreshToken: refresh_token});

    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    const userData = {
        Username: "neeraj_singh",
        Pool: userPool
    };

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    cognitoUser.refreshSession(RefreshToken, (err, session) => {
        if (err) {
            console.log(err);
        } else {
            let retObj = {
                "access_token": session.accessToken.jwtToken,
                "id_token": session.idToken.jwtToken,
                "refresh_token": session.refreshToken.token,
            }
            console.log(retObj);
        }
    })
}


function DeleteUser(username,password) {
        var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
            Username: username,
            Password: password,
        });

        var userData = {
            Username: username,
            Pool: userPool
        };
        var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

        cognitoUser.authenticateUser(authenticationDetails, {
            onSuccess: function (result) {
                cognitoUser.deleteUser((err, result) => {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log("Successfully deleted the user.");
                        console.log(result);
                    }
                });
            },
            onFailure: function (err) {
                console.log(err);
            },
        });
}


function deleteAttributes(username, password){
        var attributeList = [];
        attributeList.push("gender");
  
        var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
            Username: username,
            Password: password,
        });

        var userData = {
            Username: username,
            Pool: userPool
        };
        var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

        cognitoUser.authenticateUser(authenticationDetails, {
            onSuccess: function (result) {
                cognitoUser.deleteAttributes(attributeList, (err, result) => {
                    if (err) {
                        console.log(err)
                    } else {
                        console.log(result);
                    }
                });
            },
            onFailure: function (err) {
                console.log(err);
            },
        });
       
}


function ChangePassword(username, password, newpassword) {
        var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
            Username: username,
            Password: password,
        });

        var userData = {
            Username: username,
            Pool: userPool
        };
        var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

        cognitoUser.authenticateUser(authenticationDetails, {
            onSuccess: function (result) {
                cognitoUser.changePassword(password, newpassword, (err, result) => {
                    if (err) {
                        console.log(err);
                    } else {
                        console.log("Successfully changed password of the user.");
                        console.log(result);
                    }
                });
            },
            onFailure: function (err) {
                console.log(err);
            },
        });
}

//RegisterUser();
//Login()
//update('neeraj_singh','12345@As')
//ValidateToken('eyJraWQiOiJsa21GQW10RXIrOXlZQkdwU2pGcTZqa0N6YXRIZGlsNTJGOVMrVHVRUjRBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyZGI4YjA3NS0xZjA4LTRmODEtOTQ3Mi0zNGU0ZjQ5ZjZlZmQiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtbm9ydGgtMS5hbWF6b25hd3MuY29tXC9ldS1ub3J0aC0xX2paYlNmUVZNaiIsImNsaWVudF9pZCI6IjFsYXBmN2xkajdubmV0ZGZzbDNkaXRqaWs3Iiwib3JpZ2luX2p0aSI6ImUwOTE0ZmViLTYxODctNDA3ZS04NzE2LTkwNTc4YmIwYjgxYSIsImV2ZW50X2lkIjoiYmM4YzU0ZTYtYjZhOC00ZWJhLWEwMGItNGIwOTc3ZjdjZjBkIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTY4NDM0MjI5NiwiZXhwIjoxNjg0MzQ1ODk2LCJpYXQiOjE2ODQzNDIyOTYsImp0aSI6IjY3OTYzN2Q2LTE5NTEtNDU0NC1hOTZjLTQ5MmM2YTUzODUyOCIsInVzZXJuYW1lIjoibmVlcmFqX3NpbmdoIn0.V3WTcLeUVaPm8qckyQ9xTi5Y_RcPp0rZw0j2g9L6QyqOE6vdzKV4bE7C_swVGa91xCtAoCTIh03I0NaEdbgUEtZWWqTWdNUA6SxiS8zZObpCF9kr4rc2wbLwJqUAsd2jpO-zKY2RqDImyzA0UnD_jPXPEGEnU1QWW5u56j0F1R4PYjTDYbozguihmELAp4S4oeBTNfo_rRf4a8_oAOBibadOkGwdLnARnpOVHAZeSgONdp2ifs8uwdsrjZfy6Xu4SFkVvM3xnb7ueEhNaxeWb9cIzhbkVzq1d1lmvrhYTK3Kx8oEb8heEa2TALiNgvZOGIVJS8zFMvug7MfFKhpLKQ')
//renew('eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.eimNeeF-2eCgX2XezT2qiSU_TguMOE1OYQX1v2GD7pwrHK44uUTU4L1k9dXh-abwHuUlCaKkdCpP6hfKs3oAWTyuAFvfkW-v_UcrrRd83BCfRrVqk1HvyzSMPYDVZ7md7PgEV4suLIGo7euuSVXPqpT-RsZc6vfWFHwUaCAYEiu5zB-zqp9ZmtOd6aDwkGC-elgCM7qEdDeSqv2aDjHHEezBHjptAGvX4I451LRwLyeQsy7iUVvf9_xS1oMPI_hGaXK5WkWFCycgQbZr73m6YiQRQxdY6TmabXKLK9SxEtcqcZpcqDdO-NZMkhZQ-gorKAHFSEsPzppxd5lwKGKYQw.JO7VAmGrppMHSpxy.hOMCttDoRoUNQhjetlxiYnJD7X1O6olQ19xDPvLs8BnKODOADryf_LqjpeRAUXYvilGtzTHHYD_ttTYmyou9kcx3TI1FbE8UbdlVgk3YspRIKFtvEgV0shfFtY_PYEdHyh45Agl-kj6ZFbAkP5-kk0K7Mi1EXCtjqqe7I1eZhrU5nQH07KQFQX1a9ubZhZAgQiecSolMZervoxrCIiMXsAd_Tx_WoqV-J42_kgV_1I5DBd9mwxJG6CXBaM7-zvfiqhpBhq8Kn5alsBBLh_GqiP_EzSg-zet-hj6e13Dc5TrAwaroTb6y1Au1R3nLlZb_QfmjsfAISJ_stOTlBsIhY4JhpU9M-6NesySloIJQzmyoJL2hm55540fVPDBtf7k5eY4O-k1PcPBMvFn2riIo-7dHXcJyjNSzsE2mG-g9RJLcw5gVnlIIyK-EHqiir6WUqISu9xVxeNuzbIajjALeNX3zFaH46EdjtAxY8g2GW3P22m86UisARiD_JLNlfc_nxP2yvMWuX8HbEWiEq85pjWnY8bklNAJtSl-kaJuKjfpygzLtavAYg0rMzvfdjLS_f5sil8fuUuwAYQrJ_v6cAS4U2Rk1o1VqeGOKrOfu-j4mrNyG3UfOYsm8EWf4-7wCsmvfSdvgENuDN5inQgd2SUOjRCgWu7P6gH9UDE55VMuw8HehZObiJwrD-D9-k8q2UPdYp1X2PtjhLHSd9HZxJZEOI3jLkuk2lhqodL56ugamCFQMNHf05NjJ2vAYRa8zOSk19vvtOZIsbJlYt0p3yNxtP2kgzAu6v3UBxEl9bJ7oZk6080eTVLjfOG7c8SmhtvCroeQAbRUQ9uIsFMyHoAe9NFHgTLR-u-sg5eAraqCGbpaCIS-2P8LDuGM-Ko0rMYSskT9fCs70g0YqeVPBDBGvfnoISYx7RLNIN8-GefsVQ0_DIlYpgSo6kokfnu29yfPJsKf1ctWwOz_3k_NzaskPUz3rnfXjl9y11_VYFP4xzpDb9Ej3-xBNUgeRXbtauzpKkgv4uy_P07fV1NVZ5_ewbaOTSjGje9bkrhKDQkEIGhE5-FevqVyIH3R97xQcmzYmf8rUg1SEFYv2EJFETV8z_mN1KUXQ5vkB4uNeD0ay8JyXOk-0mV89fKmeyFsnIF1b5_w4i00mgfHBKKPbQYB8Cjqok6MC9hmnXahzGYBrz_vaM6XYLnM7l7LswLpj8LB1XEkDpT3W5E5N86llwuG38WJoEj3OCfGXkh3IvZLOpB2WH8DHpKw-8p9D5kvrf8R9cxMyuYP4CDWmw6R6.pHqrrQZdRwBBFQ7pyGSdeA')
//DeleteUser('neeraj_singh1','12345@As')
//deleteAttributes('neeraj_singh','12345@As')
//ChangePassword('neeraj_singh','12345@As','12345@As1')