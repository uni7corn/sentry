package anti.rusda.ui;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;

import anti.rusda.OverviewFragment;
import anti.rusda.DebugFragment;
import anti.rusda.EnvironmentFragment;

public class MainPagerAdapter extends FragmentStateAdapter {

    private final OverviewFragment overviewFragment;
    private final DebugFragment debugFragment;
    private final EnvironmentFragment environmentFragment;

    public MainPagerAdapter(@NonNull FragmentActivity activity,
                            OverviewFragment overview,
                            DebugFragment debug,
                            EnvironmentFragment environment) {
        super(activity);
        this.overviewFragment = overview;
        this.debugFragment = debug;
        this.environmentFragment = environment;
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        switch (position) {
            case 0: return overviewFragment;
            case 1: return debugFragment;
            case 2: return environmentFragment;
            default: return overviewFragment;
        }
    }

    @Override
    public int getItemCount() {
        return 3;
    }

    public OverviewFragment getOverviewFragment() { return overviewFragment; }
    public DebugFragment getDebugFragment() { return debugFragment; }
    public EnvironmentFragment getEnvironmentFragment() { return environmentFragment; }
}
