package anti.rusda.ui;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;

import anti.rusda.OverviewFragment;
import anti.rusda.DebugFragment;
import anti.rusda.EnvironmentFragment;

/**
 * ViewPager2 适配器。
 *
 * 关键：createFragment 必须每次 new 出新实例，绝不能持有/返回外部传入的固定实例。
 * 否则 Activity recreate（如切换主题触发的 setDefaultNightMode→recreate）时，
 * FragmentManager 会从保存状态恢复旧 fragment，而外部持有的是另一批实例，造成
 * "屏幕显示的 fragment" 与 "代码引用的 fragment" 错配，UI 更新打到不可见实例上、
 * Run Scan 按钮卡死。需要访问当前实例时用 FragmentManager.findFragmentByTag("f"+pos)。
 */
public class MainPagerAdapter extends FragmentStateAdapter {

    public MainPagerAdapter(@NonNull FragmentActivity activity) {
        super(activity);
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        switch (position) {
            case 1:  return new DebugFragment();
            case 2:  return new EnvironmentFragment();
            case 0:
            default: return new OverviewFragment();
        }
    }

    @Override
    public int getItemCount() {
        return 3;
    }
}
