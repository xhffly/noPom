package cn.seczone.tools;

import java.io.File;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;

import com.google.common.collect.Lists;

import cn.seczone.bean.LogBean;
import cn.seczone.bean.PortalDto;
import cn.seczone.bean.ScanTaskBean;
import cn.seczone.bean.StatusEnum;
import cn.seczone.common.exclusion.Constant;
import cn.seczone.config.GlobalConfig;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class ScanFileUtils {

	static final String ErrMsg = "执行异常, 请联系管理员处理";
	static final List<String> ExcludeSrcFileDir = Lists.newArrayList(".git", ".idea", ".settings", "target", ".vscode",
			".springBeans", ".factorypath", ".mvn", ".svn", ".apt_generated", "sts4-cache");

	static ThreadLocal<Boolean> HasAvailableAnalyzingFileLocal = new ThreadLocal().withInitial(() -> false);

	public static void scanPsZipDirectory(PortalDto portalDto) {
		FileUtil.OPEN_OR_LOCAL = portalDto.getScope();
		try {
			String filePath = portalDto.getFilePath();
			File rootFile = new File(filePath);
			if (!rootFile.exists() || rootFile.isFile()) {
				throw new Exception("根目录不存在,目录:" + filePath);
			}
			File[] listFiles = rootFile.listFiles();
			if (listFiles == null || listFiles.length == 0) {
				throw new Exception("根目录下没有文件,目录:" + filePath);
			}

			// 预估文件解析执行时间，针对zip源码包
			// new Thread(() -> predictExecutionTime(rootFile,
			// portalDto.getUuid())).start();
			ScanTaskBean scanTaskBean = UtilsPs.getScanTaskBean(portalDto);
			if (scanTaskBean == null) {
				log.error("[err29] scanTaskBean不存在，portalDto=" + portalDto);
				return;
			} else {
				scanTaskBean.setStatus(StatusEnum.ANALYZING.status);
			}
			new Thread(() -> {
				for (File zipFile : listFiles) {
					traversePsDir(zipFile, null, 1, portalDto, scanTaskBean);
				}
				// 空文件夹或者没有有效源码文件
				if (!HasAvailableAnalyzingFileLocal.get()) {
					if (scanTaskBean == null) {
						log.error("[err30] scanTaskBean不存在，portalDto=" + portalDto);
					} else {
						scanTaskBean.setStatus(StatusEnum.DONE.status);
					}
				}
			}).start();
		} catch (Exception e) {
			ScanTaskBean scanTaskBean = UtilsPs.getScanTaskBean(portalDto);
			if (scanTaskBean == null) {
				log.error("[err31] scanTaskBean不存在, portalDto=" + portalDto);
			} else {
				scanTaskBean.setStatus(StatusEnum.ERR.status);
				scanTaskBean.setMsg(ErrMsg);
				log.error("[err30] 任务执行异常, portalDto=" + portalDto, e);
			}
		}
	}

	public static void scanZipDirectory(String openOrLocal, String language, String license) throws Exception {
		FileUtil.OPEN_OR_LOCAL = openOrLocal;
		File rootFile = new File(FileUtil.zipDirectory);
		if (!rootFile.exists() || rootFile.isFile()) {
			throw new Exception("根目录不存在,目录:" + FileUtil.zipDirectory);
		}
		File[] listFiles = rootFile.listFiles();
		if (listFiles == null || listFiles.length == 0) {
			throw new Exception("根目录下没有文件,目录:" + FileUtil.zipDirectory);
		}

		// 预估文件解析执行时间
		GlobalConfig.STATUS.set(StatusEnum.ANALYZING.status);

		for (File zipFile : listFiles) {
			traverseDir(zipFile, "", "", "", 1, language, new StringBuilder(), license);
		}
	}

	// projectName可能是项目的上级目录也可能是项目名称
	public static void traversePsDir(File srcFile, String projectName, int level, PortalDto portalDto,
			ScanTaskBean scanTaskBean) {
		if (level == 1) {
			// oss zipGav最终生成的是 一级目录+.zip文件的名称 标识此包的gav信息，中间跳过多级目录的情况，不再拼接取其目录的名称
			// ps项目gav由portal传递
			projectName = portalDto.getArtifact();
			log.info("[start] scan project:" + projectName + " " + srcFile.getName(), UtilsPs.GROUP_ZIP_LOG);
		}
		if (srcFile.isDirectory() && !ExcludeSrcFileDir.contains(srcFile.getName())) {
			for (File sub : srcFile.listFiles()) {
				traversePsDir(sub, projectName, level + 1, portalDto, scanTaskBean);
			}
		} else if (srcFile.isFile() && srcFile.length() > 0) {
//			ProcessZipFile.processPsZipFile(srcFile, projectName, level, portalDto, scanTaskBean);//修改于21/12/13 ps的f.txt只存储a信息即可
			ProcessZipFile.processPsZipFile(srcFile, portalDto.getArtifact(), level, portalDto, scanTaskBean);
		}

		if (level == 1) {
			log.info("[end] scan project:" + FileUtil.getLastDirName(portalDto.getFilePath()) + " " + projectName,
					UtilsPs.GROUP_ZIP_LOG);
		}
	}

	/**
	 * 处理下载zip
	 * 
	 * @param srcFile
	 * @param g
	 * @param a
	 * @param v
	 * @param level
	 * @param language
	 */
	public static void traverseDir(File srcFile, String g, String a, String v, int level, String language,
			StringBuilder groupZipLog, String license) {
		if (level == 1 && srcFile.isFile()) {
			log.info(String.format("此%d级不是目录，而是文件，跳过解析", level));
			return;
		}
		String fileName = srcFile.getName();
		if (srcFile.isDirectory() && !ExcludeSrcFileDir.contains(srcFile.getName())) {
			if ("java".equalsIgnoreCase(language)) {
				if (level == 1) { // add g
					g = fileName;
					groupZipLog = new StringBuilder("[scanning scan name: " + g);
				}
				if (level == 2) { // add a
					a = fileName;
				}
			} else {// add a/v @name/name/1.0.0
				if (level == 1) { // add g
					a = fileName;
					groupZipLog = new StringBuilder("[scanning scan name: " + a);
				} else {
					a = a + "/" + fileName;
				}
			}

			for (File sub : srcFile.listFiles()) {
				traverseDir(sub, g, a, v, level + 1, language, groupZipLog, license);
			}
		}

		if (srcFile.isFile() && fileName.endsWith(".zip")) {
			String version = null;
			if ("java".equalsIgnoreCase(language)) {
				version = StringUtils.substringAfter(fileName, a + "-");
			} else {
				version = StringUtils.substringAfterLast(a, "/");
				a = StringUtils.substringBeforeLast(a, "/");
			}

			StringBuilder gav = new StringBuilder();
			if ("java".equalsIgnoreCase(language)) {
				gav.append(g).append(" ").append(a).append(" ").append(version);
				log.info("[start] gav=" + g + " " + fileName, Utils.GROUP_ZIP_LOG);
			} else {
				gav.append(a).append(" ").append(version).append(".zip");
				log.info("[start] av=" + a + " " + fileName, Utils.GROUP_ZIP_LOG);
			}
			groupZipLog.append(" " + fileName);
			ProcessZipFile.processZipFile(srcFile, gav, language, license);
		}

		if (level == 1) {
			groupZipLog.append(" end]");
			// 扫描完成的groupZipScan使用log保存，自动创建及拆分文件
			log.info(groupZipLog.toString(), Utils.GROUP_ZIP_LOG);
			// 扫描完成(不代表解析完成)的group放入队列批量保存
			Utils.getInstance().offer(
					new LogBean().logType(LogBean.GROUP_SCAN_DB).logInfo(FileUtil.zipDirectory + " " + fileName));
		}

	}

	public static void main(String[] args) {
		System.out.println(JacksonUtil.toJSon(Constant.ROOT_EXT_MAP));
	}
}
