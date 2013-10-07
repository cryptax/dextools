package com.fortiguard.hideandseek;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Button;
import android.view.View;
import android.util.Log;

public class DrJekyll extends Activity
{
    public TextView txtView;
    public Button validateBtn;
    public MrHyde hyde;

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

	txtView = (TextView) findViewById(R.id.textView1);
	validateBtn = (Button) findViewById(R.id.validateButton);

	hyde = new MrHyde(this.getApplicationContext());
	txtView.setText(hyde.whoami());

	validateBtn.setOnClickListener(new View.OnClickListener()
        {
            public void onClick(View v) 
            {                
		Log.i("HideAndSeek", "DrJekyll: calling invokeHidden");
		hyde.invokeHidden();
		txtView.setText(hyde.whoami());
		Log.i("HideAndSeek", "DrJekyll: onClick done");
            }
        });
    }

    
}
