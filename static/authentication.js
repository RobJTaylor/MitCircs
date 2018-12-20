$(function () {

    // This is the host for the backend.
    var backendHostUrl = '/';

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
                $('#logged-out').hide();
                var name = user.displayName;

                /* If the provider gives a display name, use the name for the
                personal welcome message. Otherwise, use the user's email. */
                var welcomeName = name ? name : user.email;

                user.getToken().then(function (idToken) {
                    userIdToken = idToken;

                    /* Now that the user is authenicated, fetch the notes. */
                    fetchNotes();

                    $('#user').text(welcomeName);
                    $('#logged-in').show();

                });

            } else {
                $('#logged-in').hide();
                $('#logged-out').show();

            }
            // [END onAuthStateChanged]

        });

    }

    // [START configureFirebaseLoginWidget]
    // Firebase log-in widget
    function configureFirebaseLoginWidget() {
        var uiConfig = {
            'signInSuccessUrl': '/',
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

    function fetchNotes() {
        $.ajax({
            type: 'POST',
            url: '/',
            headers: { 'Authorization': 'Bearer ' + userIdToken, },
            success: function (response) {
                console.log(response);
            },
            error: function (error) {
                console.log(error);
            }
        });
    }

    // [START signOutBtn]
    // Sign out a user
    var signOutBtn = $('#sign-out');
    signOutBtn.click(function (event) {
        event.preventDefault();

        firebase.auth().signOut().then(function () {
            console.log("Sign out successful");
        }, function (error) {
            console.log(error);
        });
    });
    // [END signOutBtn]

    configureFirebaseLogin();
    configureFirebaseLoginWidget();
});

