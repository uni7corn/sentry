package anti.rusda;

import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import anti.rusda.R;

public class OverviewFragment extends Fragment {

    private TextView scoreValue;
    private TextView scoreLabel;
    private MaterialButton scanButton;
    private LinearLayout scanProgressContainer;
    private LinearProgressIndicator scanProgress;
    private LinearLayout deviceInfoContainer;

    private int totalScore = -1;
    private int maxScore = -1;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_overview, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        scoreValue = view.findViewById(R.id.score_value);
        scoreLabel = view.findViewById(R.id.score_label);
        scanButton = view.findViewById(R.id.scan_button);
        scanProgressContainer = view.findViewById(R.id.scan_progress_container);
        scanProgress = view.findViewById(R.id.scan_progress);
        deviceInfoContainer = view.findViewById(R.id.device_info_container);
        fillDeviceInfo();
        refreshScoreDisplay();
        if (getActivity() instanceof MainActivity) {
            scanButton.setOnClickListener(((MainActivity) getActivity()).getScanClickListener());
        }
    }

    public void setScore(int total, int max) {
        this.totalScore = total;
        this.maxScore = max;
        refreshScoreDisplay();
    }

    public void setScanning(boolean scanning) {
        if (scanButton != null) scanButton.setEnabled(!scanning);
        if (scanProgressContainer != null) scanProgressContainer.setVisibility(scanning ? View.VISIBLE : View.GONE);
    }

    private void refreshScoreDisplay() {
        if (scoreValue == null) return;
        if (maxScore <= 0 || totalScore < 0) {
            scoreValue.setText("—");
            return;
        }
        int percent = (int) Math.round(100.0 * totalScore / maxScore);
        scoreValue.setText(String.valueOf(percent));
    }

    private void fillDeviceInfo() {
        if (deviceInfoContainer == null) return;
        deviceInfoContainer.removeAllViews();
        String[][] lines = {
                { "Model", Build.MODEL },
                { "Manufacturer", Build.MANUFACTURER },
                { "Device", Build.DEVICE },
                { "Android", String.valueOf(Build.VERSION.SDK_INT) },
                { "Brand", Build.BRAND },
        };
        for (String[] line : lines) {
            TextView row = new TextView(requireContext());
            row.setText(line[0] + ": " + line[1]);
            row.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium);
            int pad = (int) (12 * getResources().getDisplayMetrics().density);
            row.setPadding(0, pad / 2, 0, pad / 2);
            deviceInfoContainer.addView(row);
        }
    }
}
