package com.bugsee.shared.certificatepinning;

import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import com.bugsee.shared.task.AsyncTaskResult;
import com.commonsware.cwac.netsecurity.OkHttp3Integrator;
import com.commonsware.cwac.netsecurity.TrustManagerBuilder;
import com.datatheorem.android.trustkit.TrustKit;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;


/**
 * Created by denis.druzhinin, Bugsee Inc, <a href="https://www.bugsee.com">https://www.bugsee.com</a>
 */
public class MainActivity extends AppCompatActivity {
    private static final String TAG = MainActivity.class.getSimpleName();
    private static final String HostNameWithRightPin = "stackoverflow.com";
    private static final String HostNameWithWrongPin = "www.bugsee.com";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TrustKit.initializeWithNetworkSecurityConfiguration(this, R.xml.network_security_config);
        // OkHttp CertificatePinner
        findViewById(R.id.okhttp_check_right).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new CheckCertificateTask(SecurityApi.OkHttp).execute(true);
            }
        });

        findViewById(R.id.okhttp_check_wrong).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new CheckCertificateTask(SecurityApi.OkHttp).execute(false);
            }
        });

        // TrustKit
        findViewById(R.id.trustkit_check_right_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new CheckCertificateTask(SecurityApi.TrustKit).execute(true);
            }
        });

        findViewById(R.id.trustkit_check_wrong_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new CheckCertificateTask(SecurityApi.TrustKit).execute(false);
            }
        });

        // CWAC-NetSecurity
        findViewById(R.id.netsecurity_check_right_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new CheckCertificateTask(SecurityApi.CwacNetSecurity).execute(true);
            }
        });

        findViewById(R.id.netsecurity_check_wrong_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new CheckCertificateTask(SecurityApi.CwacNetSecurity).execute(false);
            }
        });

        // Native Android N network security configuration
        findViewById(R.id.native_check_right_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new CheckCertificateTask(SecurityApi.NativeAndroidN).execute(true);
            }
        });

        findViewById(R.id.native_check_wrong_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new CheckCertificateTask(SecurityApi.NativeAndroidN).execute(false);
            }
        });
    }

    private class CheckCertificateTask extends AsyncTask<Boolean, Void, AsyncTaskResult<Boolean>> {
        private volatile SecurityApi mSecurityApi;

        public CheckCertificateTask(SecurityApi securityApi) {
            mSecurityApi = securityApi;
        }

        @Override
        protected AsyncTaskResult<Boolean> doInBackground(Boolean... params) {
            try {
                boolean useRightCertificate = params[0];
                String hostName = useRightCertificate ? HostNameWithRightPin : HostNameWithWrongPin;

                OkHttpClient client = null;
                switch (mSecurityApi) {
                    case OkHttp:
                        String pin = useRightCertificate ? "sha256/2zKehMv7KtnGBz1d2U0bFrAOKb1aWWlrG9a0BzrOvwA=" : "sha256/afwiKY3RxoMmLkuRW1l7QsPZTJ4wDS2pdDROQjXw8ig=";
                        CertificatePinner certificatePinner = new CertificatePinner.Builder()
                                .add(hostName, pin)
                                .build();
                        client = new OkHttpClient.Builder()
                                .certificatePinner(certificatePinner)
                                .build();
                        break;
                    case TrustKit:
                        client = new OkHttpClient().newBuilder()
                                .sslSocketFactory(TrustKit.getInstance().getSSLSocketFactory(hostName), TrustKit.getInstance().getTrustManager(hostName))
                                .build();
                        break;
                    case NativeAndroidN:
                        client = new OkHttpClient.Builder()
                                .build();
                        break;
                    case CwacNetSecurity:
                        TrustManagerBuilder trustManagerBuilder = new TrustManagerBuilder().withManifestConfig(MainActivity.this);
                        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder();
                        OkHttp3Integrator.applyTo(trustManagerBuilder, clientBuilder);
                        client = clientBuilder.build();
                        break;
                }
                Request request = new Request.Builder()
                        .url("https://" + hostName)
                        .build();
                client.newCall(request).execute();
            } catch (Exception e) {
                return new AsyncTaskResult<>(e);
            }
            return new AsyncTaskResult<>(true);
        }

        @Override
        protected void onPostExecute(AsyncTaskResult result) {
            super.onPostExecute(result);
            if (result.hasError()) {
                Log.e(TAG, "Task failed", result.getError());
                Toast.makeText(MainActivity.this, "Task finished with error (see logs for details)", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(MainActivity.this, "Task finished successfully", Toast.LENGTH_SHORT).show();
            }
        }
    }
}
