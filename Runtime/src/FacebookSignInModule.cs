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
        private IRGNRolesCore _rgnCore;

        public void SetRGNCore(IRGNRolesCore rgnCore)
        {
            _rgnCore = rgnCore;
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
                _rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, Initialized the Facebook SDK");
            }
            else
            {
                _rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, Failed to Initialize the Facebook SDK");
            }
        }

        private void OnHideUnity(bool isGameShown)
        {
            if (!isGameShown)
            {
                // Pause the game - we will need to hide
                _rgnCore.Dependencies.Time.timeScale = 0;
            }
            else
            {
                // Resume the game - we're getting focus again
                _rgnCore.Dependencies.Time.timeScale = 1;
            }
        }

        public void SignOut()
        {
            if (FB.IsLoggedIn)
            {
                FB.LogOut();
            }
            _rgnCore.SignOutRGN();
        }

        public void TryToSignIn(bool tryToLinkToCurrentAccount = false)
        {
            var perms = new List<string> { "public_profile", "email" };
            FB.LogInWithReadPermissions(perms, result => {
                if (FB.IsLoggedIn)
                {
                    AccessToken aToken = AccessToken.CurrentAccessToken;

                    if (FB.Mobile.CurrentProfile() != null)
                    {
                        _rgnCore.Dependencies.Logger.Log($"[FacebookSignInModule]: FB, name: {FB.Mobile.CurrentProfile().Name}, email: {FB.Mobile.CurrentProfile().Email}");
                    }

                    if (aToken != null && aToken.Permissions.Contains("email"))
                    {
                        if (tryToLinkToCurrentAccount)
                        {
                            _rgnCore.CanTheUserBeLinkedAsync(FB.Mobile.CurrentProfile().Email).ContinueWith(checkLinkResult => {
                                if (checkLinkResult.IsCanceled)
                                {
                                    _rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: IsUserCanBeLinkedAsync was cancelled");
                                    SignOut();
                                    return;
                                }

                                if (checkLinkResult.IsFaulted)
                                {
                                    Utility.ExceptionHelper.PrintToLog(_rgnCore.Dependencies.Logger, checkLinkResult.Exception);
                                    SignOut();
                                    _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                                    return;
                                }

                                bool canBeLinked = checkLinkResult.Result;
                                if (!canBeLinked)
                                {
                                    _rgnCore.Dependencies.Logger.LogError("[FacebookSignInModule]: The User can not be linked");
                                    SignOut();
                                    _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
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
                        _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    }
                }
                else
                {
                    _rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, User cancelled login");
                    _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                }
            });
        }

        private void LinkFacebookAccountToFirebase(string accessToken)
        {
            _rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, Attempting to sign with Facebook...");

            var credential = _rgnCore.Auth.faceBookAuthProvider.GetCredential(accessToken);

            _rgnCore.Auth.CurrentUser.LinkAndRetrieveDataWithCredentialAsync(credential).ContinueWith(task => {
                if (task.IsCanceled)
                {
                    _rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: LinkAndRetrieveDataWithCredentialAsync was cancelled");
                    if (FB.IsLoggedIn)
                    {
                        FB.LogOut();
                    }
                    return;
                }

                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(_rgnCore.Dependencies.Logger, task.Exception);
                    FirebaseAccountLinkException firebaseAccountLinkException = task.Exception.InnerException as FirebaseAccountLinkException;
                    if (firebaseAccountLinkException != null && firebaseAccountLinkException.ErrorCode == (int)AuthError.CredentialAlreadyInUse)
                    {
                        if (FB.IsLoggedIn)
                        {
                            FB.LogOut();
                        }
                        _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                        return;
                    }

                    FirebaseException firebaseException = task.Exception.InnerException as FirebaseException;

                    if (firebaseException != null)
                    {
                        EnumLoginError loginError = (AuthError)firebaseException.ErrorCode switch {
                            AuthError.EmailAlreadyInUse => EnumLoginError.AccountAlreadyLinked,
                            AuthError.RequiresRecentLogin => EnumLoginError.AccountNeedsRecentLogin,
                            _ => EnumLoginError.Unknown
                        };

                        if (FB.IsLoggedIn)
                        {
                            FB.LogOut();
                        }
                        _rgnCore.SetAuthCompletion(EnumLoginState.Error, loginError);
                        return;
                    }

                    if (FB.IsLoggedIn)
                    {
                        FB.LogOut();
                    }

                    _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                _rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: LinkWith Facebook Successful. " + _rgnCore.Auth.CurrentUser.UserId + " ");

                _rgnCore.Auth.CurrentUser.TokenAsync(false).ContinueWith(task1 => {
                    if (task1.IsCanceled)
                    {
                        _rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: TokenAsync was cancelled");
                        SignOut();
                        return;
                    }
                    if (task1.IsFaulted)
                    {
                        Utility.ExceptionHelper.PrintToLog(_rgnCore.Dependencies.Logger, task1.Exception);
                        SignOut();
                        _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                        return;
                    }

                    _rgnCore.LinkWithProviderAsync(false, task1.Result).ContinueWith(task2 => {
                        _rgnCore.SetAuthCompletion(EnumLoginState.Success, EnumLoginError.Ok);
                    },
                    TaskScheduler.FromCurrentSynchronizationContext());
                },
                TaskScheduler.FromCurrentSynchronizationContext());
            });
        }

        private void SignInWithFacebookOnFirebase(string accessToken)
        {
            _rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: FB, Attempting to sign with Facebook...");

            var credential = _rgnCore.Auth.faceBookAuthProvider.GetCredential(accessToken);

            _rgnCore.Auth.SignInWithCredentialAsync(credential).ContinueWith(task => {
                if (task.IsCanceled)
                {
                    _rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: SignInWithCredentialAsync was cancelled");
                    SignOut();
                    return;
                }
                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(_rgnCore.Dependencies.Logger, task.Exception);
                    FirebaseException firebaseException = task.Exception.InnerException.InnerException as FirebaseException;
                    if (firebaseException != null && firebaseException.ErrorCode == (int)AuthError.AccountExistsWithDifferentCredentials)
                    {
                        if (FB.IsLoggedIn)
                        {
                            FB.LogOut();
                        }
                        _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountExistsWithDifferentCredentials);
                        return;
                    }
                    SignOut();
                    _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                _rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: Sign In with Facebook Successful. " + _rgnCore.Auth.CurrentUser.UserId);

                _rgnCore.Auth.CurrentUser.TokenAsync(false).ContinueWith(task1 => {
                    if (task1.IsCanceled)
                    {
                        _rgnCore.Dependencies.Logger.LogWarning("[FacebookSignInModule]: TokenAsync was cancelled");
                        SignOut();
                        return;
                    }

                    if (task1.IsFaulted)
                    {
                        Utility.ExceptionHelper.PrintToLog(_rgnCore.Dependencies.Logger, task1.Exception);
                        SignOut();
                        _rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                        return;
                    }

                    _rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: Facebook, userToken " + task1.Result);

                    _rgnCore.CreateCustomTokenAsync(task1.Result).ContinueWith(task2 => {
                        _rgnCore.Dependencies.Logger.Log("[FacebookSignInModule]: Facebook, masterToken " + task2.Result);

                        _rgnCore.ReadyMasterAuth.SignInWithCustomTokenAsync(task2.Result);
                    },
                    TaskScheduler.FromCurrentSynchronizationContext());
                },
                TaskScheduler.FromCurrentSynchronizationContext());
            },
            TaskScheduler.FromCurrentSynchronizationContext());
        }
    }
}
