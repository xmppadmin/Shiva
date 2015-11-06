-- SQL file for main database.

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


--
-- Database: `Shiva`
--

-- --------------------------------------------------------

-- Creating database and using it

CREATE DATABASE `Shiva` COLLATE=utf8mb4_unicode_ci;
USE `Shiva`;

--
-- Table structure for table `attachment`
--

CREATE TABLE IF NOT EXISTS `attachment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `md5` char(32) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `attachment_file_name` varchar(200) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `attachment_file_path` mediumtext NOT NULL,
  `attachment_file_type` varchar(50) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `spam_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `spam_id` (`spam_id`),
  KEY `md5` (`md5`),
  KEY `attachment_file_name` (`attachment_file_name`)
) ENGINE=InnoDB DEFAULT COLLATE=utf8mb4_unicode_ci AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `inline`
--

CREATE TABLE IF NOT EXISTS `inline` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `md5` char(32) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `inline_file_name` varchar(200) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `inline_file_path` mediumtext NOT NULL,
  `spam_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `spam_id` (`spam_id`),
  KEY `md5` (`md5`),
  KEY `inline_file_name` (`inline_file_name`)
) ENGINE=InnoDB DEFAULT COLLATE=utf8mb4_unicode_ci AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `ip`
--

CREATE TABLE IF NOT EXISTS `ip` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `sourceIP` varchar(16) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `sourceIP` (`sourceIP`),
  KEY `date` (`date`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `ip_spam`
--

CREATE TABLE IF NOT EXISTS `ip_spam` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_id` int(11) NOT NULL,
  `spam_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ip_id` (`ip_id`),
  KEY `spam_id` (`spam_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `links`
--

CREATE TABLE IF NOT EXISTS `links` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `hyperLink` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `longHyperLink` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `spam_id` char(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `spam_id` (`spam_id`),
  KEY `hyperLink` (`hyperLink`),
  KEY `date` (`date`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;


-- --------------------------------------------------------

--
-- Table structure for table `relay`
--

CREATE TABLE IF NOT EXISTS `relay` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `firstRelayed` datetime NOT NULL COMMENT 'date of first relay',
  `lastRelayed` datetime NOT NULL COMMENT 'date of last relay',
  `totalRelayed` int(11) NOT NULL DEFAULT '0' COMMENT 'Total Mails Relayed Till Date',
  `spam_id` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `sensorID` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `spam_id` (`spam_id`),
  KEY `sensorID` (`sensorID`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `sdate`
--

CREATE TABLE IF NOT EXISTS `sdate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `firstSeen` datetime NOT NULL COMMENT 'First Occurance of Spam',
  `lastSeen` datetime NOT NULL COMMENT 'Last Occurance of Spam',
  `todaysCounter` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `firstSeen` (`firstSeen`),
  KEY `lastSeen` (`lastSeen`),
  KEY `date` (`date`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `sdate_spam`
--

CREATE TABLE IF NOT EXISTS `sdate_spam` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `spam_id` char(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `date_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `spam_id` (`spam_id`),
  KEY `date_id` (`date_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `sensor`
--

CREATE TABLE IF NOT EXISTS `sensor` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `sensorID` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Shiva sensor id',
  PRIMARY KEY (`id`),
  KEY `sensorID` (`sensorID`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `sensor_spam`
--

CREATE TABLE IF NOT EXISTS `sensor_spam` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sensor_id` int(11) NOT NULL,
  `spam_id` char(32)  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `sensor_id` (`sensor_id`),
  KEY `spam_id` (`spam_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `spam`
--

CREATE TABLE IF NOT EXISTS `spam` (
  `id` char(32) NOT NULL COMMENT 'Md5 of combination of fields',
  `from` varchar(200) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `subject` varchar(200) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `to` longtext CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `textMessage` mediumtext CHARACTER SET utf8 COLLATE utf8_unicode_ci COMMENT 'body of spam in text format',
  `htmlMessage` mediumtext CHARACTER SET utf8 COLLATE utf8_unicode_ci COMMENT 'body of spam in html format',
  `totalCounter` int(11) NOT NULL COMMENT 'total count of spam till date',
  `ssdeep` varchar(120) DEFAULT NULL COMMENT 'SSDeep hash of the mail',
  `headers` text NOT NULL COMMENT 'Header of Spam',
  `length` int(11) NOT NULL COMMENT 'Length of the spam',
  `shivaScore` float DEFAULT -1.0 NOT NULL COMMENT 'computed phishing score',
  `spamassassinScore` float DEFAULT -1.0 NOT NULL COMMENT 'spamassassin Bayes phishing score',
  `phishingHumanCheck` BOOL COMMENT 'messaged marked as phishing by human',
  `derivedPhishingStatus` BOOL DEFAULT NULL COMMENT 'status computed for message: NULL - not assigned, true - phishing, false - spam',
  PRIMARY KEY (`id`),
  KEY `subject` (`subject`),
  KEY `totalCounter` (`totalCounter`),
  KEY `headers` (`headers`(767)),
  KEY `textMessage` (`textMessage`(255)),
  KEY `htmlMessage` (`htmlMessage`(255))
) ENGINE=InnoDB DEFAULT COLLATE=utf8mb4_unicode_ci;

-- TODO triger on update phishingHumanCheck

-- --------------------------------------------------------

--
-- Table structure for table `whitelist`
--

CREATE TABLE IF NOT EXISTS `whitelist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `recipients` mediumtext CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT COLLATE=utf8mb4_unicode_ci AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `learning state`
--

CREATE TABLE IF NOT EXISTS `learningreport` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `learningDate` datetime NOT NULL,
  `learningMailCount` int(10) NOT NULL,
  `spamassassinStatus` char(10),
  `shivaStatus` char(10),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT COLLATE=utf8mb4_unicode_ci AUTO_INCREMENT=1 ;

-- --------------------------------------------------------


-- --------------------------------------------------------

--
-- Table structure for table `rules`
--

CREATE TABLE IF NOT EXISTS `rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `code` char(10) NOT NULL,
  `boost` int(5) DEFAULT 1,
  `description`  mediumtext CHARACTER SET utf8 COLLATE utf8_unicode_ci COMMENT 'description of the rule',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT COLLATE=utf8mb4_unicode_ci AUTO_INCREMENT=1 ;


-- --------------------------------------------------------

-- --------------------------------------------------------

--
-- Table structure for table `learning results`
--

CREATE TABLE IF NOT EXISTS `learningresults` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ruleId` int(11) NOT NULL,
  `spamId` char(32) NOT NULL,
  `result` int(11) NOT NULL COMMENT 'result of the rule',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 ;


-- --------------------------------------------------------

--
-- Overview
--
CREATE OR REPLACE VIEW spam_overview_view AS
SELECT spam.id,sdate.firstSeen,sdate.lastSeen,spam.subject,spam.shivaScore,spam.spamassassinScore,sensor.sensorID,spam.derivedPhishingStatus
FROM spam
  INNER JOIN sdate_spam ON sdate_spam.spam_id = spam.id 
  INNER JOIN sdate ON sdate_spam.id = sdate.id 
  INNER JOIN sensor_spam ON spam.id = sensor_spam.spam_id
  INNER JOIN sensor ON sensor_spam.sensor_id = sensor.id
  ORDER BY sdate.lastSeen DESC;


-- --------------------------------------------------------

--
-- view used for statistics computations
--
CREATE OR REPLACE VIEW rules_overview_view AS
SELECT r.code,se.sensorID,sum(if(lr.result < 0,0,1)) as result 
FROM spam s 
 INNER JOIN learningresults lr on s.id = lr.spamId 
 INNER JOIN rules r on r.id = lr.ruleId 
 INNER JOIN sensor_spam sse on s.id = sse.spam_id 
 INNER JOIN sensor se on sse.sensor_id = se.id 
GROUP BY se.sensorID,r.code,r.description;

-- ---------------------------------------------------------
--
-- view used for rule integrity checking
-- if any line is returned, there is inconsistency in stored rules result
-- and deep relearning must be performed
-- Inconsitency can be caused by adding new rules to honeypot without deep relearn
--
CREATE OR REPLACE VIEW ruleresults_integrity_check_view AS
SELECT spamId
  FROM learningresults 
  GROUP BY spamId 
  HAVING (select count(*) from rules) <> count(ruleId) 
    OR (select count(*) from rules) <> count(distinct ruleId)
UNION
  SELECT id FROM spam WHERE id NOT IN (SELECT spamId FROM learningresults) 
UNION 
  SELECT spamId FROM learningresults WHERE spamId NOT IN (SELECT id FROM spam);