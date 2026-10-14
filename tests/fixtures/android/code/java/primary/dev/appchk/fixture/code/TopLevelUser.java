package dev.appchk.fixture.code;

/** Uses the class in the default package. */
class TopLevelUser {
    void use() {
        try {
            Class.forName("TopLevel");
        } catch (ClassNotFoundException ignored) {
            // The fixture is never run.
        }
    }
}
