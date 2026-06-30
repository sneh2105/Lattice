"""A research crew with file system and web access."""
from crewai.tools import BaseTool
from crewai import Agent

class FileSystemReadTool(BaseTool):
    name = "read_local_files"
    description = "Read files from the local research directory for analysis"

class WebScraperTool(BaseTool):
    name = "scrape_website"
    description = "Scrape and extract content from any public website URL"

class ReportSaveTool(BaseTool):
    name = "save_report"
    description = "Write the final research report to disk"
