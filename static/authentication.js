//Firebase authentication setup
var config = {
    apiKey: "AIzaSyBpbVNSh-Fd6Rg51Hmm6quZ_mJWQ-7hGVM",
    authDomain: "mitcircs-rt.firebaseapp.com",
    databaseURL: "https://mitcircs-rt.firebaseio.com",
    projectId: "mitcircs-rt",
    storageBucket: "mitcircs-rt.appspot.com",
    messagingSenderId: "797167968095"
};
firebase.initializeApp(config);

// FirebaseUI config.
var uiConfig = {
    signInSuccessUrl: 'https://mitcircs.robtaylor.info/dashboard',
    signInOptions: [
        // Leave the lines as is for the providers you want to offer your users.
        firebase.auth.GoogleAuthProvider.PROVIDER_ID,
        firebase.auth.FacebookAuthProvider.PROVIDER_ID,
        firebase.auth.GithubAuthProvider.PROVIDER_ID,
        firebase.auth.EmailAuthProvider.PROVIDER_ID
    ],
    // tosUrl and privacyPolicyUrl accept either url string or a callback
    // function.
    // Terms of service url/callback.
    tosUrl: 'https://mitcircs.robtaylor.info',
    // Privacy policy url/callback.
    privacyPolicyUrl: function () {
        window.location.assign('https://mitcircs.robtaylor.info');
    }
};

// Initialize the FirebaseUI Widget using Firebase.
var ui = new firebaseui.auth.AuthUI(firebase.auth());
// The start method will wait until the DOM is loaded.
ui.start('#firebaseui-auth-container', uiConfig);