package com.google.firebase.auth;

/** Stands in for Firebase Authentication's class of this name. */
public class FirebaseAuth {
    public static FirebaseAuth getInstance() {
        return new FirebaseAuth();
    }

    public Object createUserWithEmailAndPassword(String email, String password) {
        return null;
    }

    public FirebaseUser getCurrentUser() {
        return new FirebaseUser();
    }
}
