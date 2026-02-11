package anti.rusda.detector;

import java.util.ArrayList;
import java.util.List;

public class DetectionResult {
    public static final int STATUS_NORMAL = 0;
    public static final int STATUS_WARNING = 1;
    public static final int STATUS_DANGER = 2;

    /** 该项满分（用于计算总分，默认 10） */
    public static final int DEFAULT_MAX_SCORE = 10;

    private String title;
    private String description;
    private int status;
    private int maxScore;
    private List<String> details;
    private boolean expanded;
    /** 若为 true，WARNING 时仍给满分（只警告不扣分） */
    private boolean warnOnly;

    public DetectionResult(String title, String description, int status) {
        this(title, description, status, DEFAULT_MAX_SCORE);
    }

    public DetectionResult(String title, String description, int status, int maxScore) {
        this.title = title;
        this.description = description;
        this.status = status;
        this.maxScore = maxScore > 0 ? maxScore : DEFAULT_MAX_SCORE;
        this.details = new ArrayList<>();
        this.expanded = false;
    }

    public DetectionResult(String title, String description, int status, List<String> details) {
        this(title, description, status, DEFAULT_MAX_SCORE, details);
    }

    public DetectionResult(String title, String description, int status, int maxScore, List<String> details) {
        this(title, description, status, maxScore, details, false);
    }

    public DetectionResult(String title, String description, int status, int maxScore, List<String> details, boolean warnOnly) {
        this.title = title;
        this.description = description;
        this.status = status;
        this.maxScore = maxScore > 0 ? maxScore : DEFAULT_MAX_SCORE;
        this.details = details != null ? details : new ArrayList<>();
        this.expanded = false;
        this.warnOnly = warnOnly;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public List<String> getDetails() {
        return details;
    }

    public void setDetails(List<String> details) {
        this.details = details;
    }

    public void addDetail(String detail) {
        if (this.details == null) {
            this.details = new ArrayList<>();
        }
        this.details.add(detail);
    }

    public boolean isExpanded() {
        return expanded;
    }

    public void setExpanded(boolean expanded) {
        this.expanded = expanded;
    }

    /** 该项满分 */
    public int getMaxScore() {
        return maxScore;
    }

    /** 根据状态得到该项得分：NORMAL=满分，WARNING=一半（warnOnly 时为满分），DANGER=0 */
    public int getEarnedScore() {
        switch (status) {
            case STATUS_NORMAL:
                return maxScore;
            case STATUS_WARNING:
                return warnOnly ? maxScore : (maxScore / 2);
            case STATUS_DANGER:
            default:
                return 0;
        }
    }

    public String getStatusText() {
        switch (status) {
            case STATUS_NORMAL:
                return "Normal";
            case STATUS_WARNING:
                return "Warning";
            case STATUS_DANGER:
                return "Danger";
            default:
                return "Unknown";
        }
    }
}
