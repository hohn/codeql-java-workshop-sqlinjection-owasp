class EditText {

    public String getText() {
        return "EditText []";
    }

}

public class CSInjection {

	EditText username;
	EditText password;

    public void onClick(int arg0) {
        switch (arg0) {

            case 1:

                String CheckName = username.getText().toString();
                String CheckPass = password.getText().toString();

        }
    }
}
