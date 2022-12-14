using Facebook.Unity;
using Firebase;
using Firebase.Auth;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RGN.Modules.SignIn
{
    public class FacebookSignInModule : BaseModule<FacebookSignInModule>, IRGNModule
    {
        private IRGNRolesCore rgnCore;

        public void SetRGNCore(IRGNRolesCore rgnCore)
        {
            this.rgnCore = rgnCore;
        }

        public void Init()
        {
            if (!FB.IsInitialized)
            {
                // Initialize the Facebook SDK
                FB.Init(InitCallback, OnHideUnity);
            }
            else
            {
                // Already initialized, signal an app activation App Event
                FB.ActivateApp();
            }
        }
        public void Dispose() { }

        private void InitCallback()
        {
            if (FB.IsInitialized)
            {
                // Signal an app activation App Event
                FB.ActivateApp();
                rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, Initialized the Facebook SDK");
            }
            else
            {
                rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, Failed to Initialize the Facebook SDK");
            }
        }

        private void OnHideUnity(bool isGameShown)
        {
            if (!isGameShown)
            {
                // Pause the game - we will need to hide
                rgnCore.Dependencies.Time.timeScale = 0;
            }
            else
            {
                // Resume the game - we're getting focus again
                rgnCore.Dependencies.Time.timeScale = 1;
            }
        }

        public void SignOutFromFacebook()
        {
            if (FB.IsLoggedIn)
            {
                FB.LogOut();
            }
            rgnCore.SignOutRGN();
        }

        public void OnSignInFacebook(bool isLink = false)
        {
            var perms = new List<string> { "public_profile", "email" };
            FB.LogInWithReadPermissions(perms, result => {
                if (FB.IsLoggedIn)
                {
                    AccessToken aToken = AccessToken.CurrentAccessToken;

                    if (FB.Mobile.CurrentProfile() != null)
                    {
                        rgnCore.Dependencies.Logger.Log($"[FacebookSignInModule]: FB, name: {FB.Mobile.CurrentProfile().Name}, email: {FB.Mobile.CurrentProfile().Email}");
                    }

                    if (aToken != null && aToken.Permissions.Contains("email"))
                    {
                        if (isLink)
                        {
                            rgnCore.IsUserCanBeLinkedAsync(FB.Mobile.CurrentProfile().Email).ContinueWith(checkLinkResult => {
                                if (checkLinkResult.IsCanceled)
                                {
                                    rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: IsUserCanBeLinkedAsync was cancelled");
                                    SignOutFromFacebook();
                                    return;
                                }

                                if (checkLinkResult.IsFaulted)
                                {
                                    Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, checkLinkResult.Exception);
                                    SignOutFromFacebook();
                                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                                    return;
                                }

                                bool canBeLinked = (bool)checkLinkResult.Result.Data;
                                if (!canBeLinked)
                                {
                                    SignOutFromFacebook();
                                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                                    return;
                                }

                                LinkFacebookAccountToFirebase(aToken.TokenString);
                            },
                            TaskScheduler.FromCurrentSynchronizationContext());
                        }
                        else
                        {
                            SignInWithFacebookOnFirebase(aToken.TokenString);
                        }
                    }
                    else
                    {
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    }
                }
                else
                {
                    rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, User cancelled login");
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                }
            });
        }

        private void LinkFacebookAccountToFirebase(string accessToken)
        {
            rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, Attempting to sign with Facebook...");

            var credential = rgnCore.Auth.faceBookAuthProvider.GetCredential(accessToken);

            rgnCore.Auth.CurrentUser.LinkAndRetrieveDataWithCredentialAsync(credential).ContinueWith(task => {
                if (task.IsCanceled)
                {
                    rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: LinkAndRetrieveDataWithCredentialAsync was cancelled");
                    if (FB.IsLoggedIn)
                    {
                        FB.LogOut();
                    }
                    return;
                }

                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task.Exception);
                    FirebaseAccountLinkException firebaseAccountLinkException = task.Exception.InnerException as FirebaseAccountLinkException;
                    if (firebaseAccountLinkException != null && firebaseAccountLinkException.ErrorCode == (int)AuthError.CredentialAlreadyInUse)
                    {
                        if (FB.IsLoggedIn)
                        {
                            FB.LogOut();
                        }
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                        return;
                    }

                    FirebaseException firebaseException = task.Exception.InnerException as FirebaseException;
                    if (firebaseException != null && firebaseException.ErrorCode == (int)AuthError.EmailAlreadyInUse)
                    {
                        if (FB.IsLoggedIn)
                        {
                            FB.LogOut();
                        }
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                        return;
                    }

                    if (FB.IsLoggedIn)
                    {
                        FB.LogOut();
                    }

                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: LinkWith Facebook Successful. " + rgnCore.Auth.CurrentUser.UserId + " ");

                rgnCore.Auth.CurrentUser.TokenAsync(false).ContinueWith(task1 => {
                    if (task1.IsCanceled)
                    {
                        rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: TokenAsync was cancelled");
                        SignOutFromFacebook();
                        return;
                    }
                    if (task1.IsFaulted)
                    {
                        Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task1.Exception);
                        SignOutFromFacebook();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                        return;
                    }

                    rgnCore.LinkWithProviderAsync(false, task1.Result).ContinueWith(task2 => {
                        rgnCore.SetAuthCompletion(EnumLoginState.Success, EnumLoginError.Ok);
                    },
                    TaskScheduler.FromCurrentSynchronizationContext());
                },
                TaskScheduler.FromCurrentSynchronizationContext());
            });
        }

        private void SignInWithFacebookOnFirebase(string accessToken)
        {
            rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, Attempting to sign with Facebook...");

            var credential = rgnCore.Auth.faceBookAuthProvider.GetCredential(accessToken);

            rgnCore.Auth.SignInWithCredentialAsync(credential).ContinueWith(task => {
                if (task.IsCanceled)
                {
                    rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: SignInWithCredentialAsync was cancelled");
                    SignOutFromFacebook();
                    return;
                }
                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task.Exception);
                    FirebaseException firebaseException = task.Exception.InnerException.InnerException as FirebaseException;
                    if (firebaseException != null && firebaseException.ErrorCode == (int)AuthError.AccountExistsWithDifferentCredentials)
                    {
                        if (FB.IsLoggedIn)
                        {
                            FB.LogOut();
                        }
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountExistsWithDifferentCredentials);
                        return;
                    }
                    SignOutFromFacebook();
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: Sign In with Facebook Successful. " + rgnCore.Auth.CurrentUser.UserId);

                rgnCore.Auth.CurrentUser.TokenAsync(false).ContinueWith(task1 => {
                    if (task1.IsCanceled)
                    {
                        rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: TokenAsync was cancelled");
                        SignOutFromFacebook();
                        return;
                    }

                    if (task1.IsFaulted)
                    {
                        Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task1.Exception);
                        SignOutFromFacebook();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                        return;
                    }

                    rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: Facebook, userToken " + task1.Result);

                    rgnCore.CreateCustomTokenAsync(task1.Result).ContinueWith(task2 => {
                        rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: Facebook, masterToken " + task2.Result);

                        rgnCore.ReadyMasterAuth.SignInWithCustomTokenAsync(task2.Result);
                    },
                    TaskScheduler.FromCurrentSynchronizationContext());
                },
                TaskScheduler.FromCurrentSynchronizationContext());
            },
            TaskScheduler.FromCurrentSynchronizationContext());
        }
    }
}
