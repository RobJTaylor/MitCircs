$(function () {

    // This is the host for the backend.
    var backendHostUrl = 'https://mitcircs.robtaylor.info';

    // Initialize Firebase
    var config = {
        apiKey: "AIzaSyBpbVNSh-Fd6Rg51Hmm6quZ_mJWQ-7hGVM",
        authDomain: "mitcircs-rt.firebaseapp.com",
        databaseURL: "https://mitcircs-rt.firebaseio.com",
        projectId: "mitcircs-rt",
        storageBucket: "mitcircs-rt.appspot.com",
        messagingSenderId: "797167968095"
    };

    // This is passed into the backend to authenticate the user.
    var userIdToken = null;

    // Firebase log-in
    function configureFirebaseLogin() {

        firebase.initializeApp(config);
    
        // [START onAuthStateChanged]
        firebase.auth().onAuthStateChanged(function (user) {
            if (user) {
                var name = user.displayName;
    
                    /* If the provider gives a display name, use the name for the
                    personal welcome message. Otherwise, use the user's email. */
                    var welcomeName = name ? name : user.email;
    
                    user.getToken().then(function (idToken) {
                        userIdToken = idToken;
                        user_name = user.name || user.email;
                        user_email = user.email;
    
                        /* Now that the user is authenicated, fetch the notes. */
                        ajaxToken(userIdToken, user_name, user_email);
                    });
    
                } else {
    
                }
                // [END onAuthStateChanged]
    
            });
    
        }

    function configureFirebaseWidget() {
        var uiConfig = {
            'signInSuccessUrl': '/dashboard',
            'signInOptions': [
                // Leave the lines as is for the providers you want to offer your users.
                firebase.auth.GoogleAuthProvider.PROVIDER_ID,
                firebase.auth.FacebookAuthProvider.PROVIDER_ID,
                firebase.auth.GithubAuthProvider.PROVIDER_ID,
                firebase.auth.EmailAuthProvider.PROVIDER_ID
            ],
            // Terms of service url
            'tosUrl': 'https://mitcircs.robtaylor.info',
        };

        var ui = new firebaseui.auth.AuthUI(firebase.auth());
        ui.start('#firebaseui-auth-container', uiConfig);
    }

    function ajaxToken(userIdToken, user_name, user_email) {
        $.ajax({
            type: 'POST',
            url: '/',
            headers: { 
                'Authorization': 'Bearer ' + userIdToken, 
                'Email': user_email, 
                'Username': user_name,
            },
            success: function (response) {
                console.log(response);
                window.location.href = '/dashboard';
            },
            error: function (error) {
                console.log(error);
            }
        });
    }

    $('#signOut').click(function(e) {
        configureFirebaseLogin();
        firebase.auth().signOut().then(function () {
            console.log("Sign out successful");
            window.location.href = '/sign-out';
        }, function (error) {
            console.log(error);
        });
    });

    if (window.location.pathname == '/') {
        configureFirebaseLogin();
        configureFirebaseWidget();
    }
});

