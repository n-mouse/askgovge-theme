# -*- encoding : utf-8 -*-
# Add a callback - to be executed before each request in development,
# and at startup in production - to patch existing app classes.
# Doing so in init/environment.rb wouldn't work in development, since
# classes are reloaded, but initialization is not run each time.
# See http://stackoverflow.com/questions/7072758/plugin-not-reloading-in-development-mode
#
Rails.configuration.to_prepare do

 IncomingMessage.class_eval do

      def get_body_for_html_display(collapse_quoted_sections = true)
        text = get_main_body_text_unfolded
        folded_quoted_text = get_main_body_text_folded

        if collapse_quoted_sections
          text = folded_quoted_text
        end
        text = MySociety::Format.simplify_angle_bracketed_urls(text)
        text = CGI.escapeHTML(text)
        text = MySociety::Format.make_clickable(text, :contract => 1)


        email_pattern = Regexp.escape(_("email address"))
        mobile_pattern = Regexp.escape(_("mobile number"))
        text.gsub!(/\[(#{email_pattern}|#{mobile_pattern})\]/,
                   '[<a href="/help/officers#mobiles">\1</a>]')

        if collapse_quoted_sections
          text = text.gsub(/(\s*FOLDED_QUOTED_SECTION\s*)+/m, "FOLDED_QUOTED_SECTION")
          text.strip!
          if text == "FOLDED_QUOTED_SECTION"
            text = "[Subject only] " + CGI.escapeHTML(self.subject || '') + text
          end
          text = text.gsub(/FOLDED_QUOTED_SECTION/, "\n\n" + '<span class="unfold_link"><a href="?unfold=1#incoming-'+self.id.to_s+'">'+_("show quoted sections")+'</a></span>' + "\n\n")
        else
          if folded_quoted_text.include?('FOLDED_QUOTED_SECTION')
            text = text + "\n\n" + '<span class="unfold_link"><a href="?#incoming-'+self.id.to_s+'">'+_("hide quoted sections")+'</a></span>'
          end
        end
        text.strip!

        text = ActionController::Base.helpers.simple_format(text)
        #if text.match(/This is the mail system at host askgov.ge/)
          #if text.match(/Try resending the message in a few minutes/)
            #text = "<p class='delivery-error'>წერილის მიწოდება დროებითი ტექნიკური ხარვეზის გამო ვერ მოხერხდა. მოგვიანებით, გაგზავნას კიდევ ერთხელ ვცდით</p>"
          if text.match(/I'm sorry to (have to )?inform you that/) || text.match(/email address you entered couldn't be found/)
            text = "<p class='delivery-error'>გაურკვეველი ტექნიკური მიზეზის გამო, წერილის მიწოდება ვერ მოხერხდა</p>"
          end
        #end
        text.html_safe
      end

    end



  InfoRequest.class_eval do
    def well_formed_title?
      true
    end
  end
   
  OutgoingMessage.class_eval do
    def body_uses_mixed_capitals
      true
    end
  end
   
  Comment.class_eval do
    def check_body_uses_mixed_capitals
      true
    end
  end
  
  PublicBodyDerivedFields.class_eval do
    def set_first_letter
      unless name.blank?
        # we use a regex to ensure it works with utf-8/multi-byte
        new_first_letter = name.scan(/^./mu)[0]
        if new_first_letter != first_letter
          self.first_letter = new_first_letter
        end
      end
    end
  end

  # Example of adding a default text to each message
  # OutgoingMessage.class_eval do
  #   # Add intro paragraph to new request template
  #   def default_letter
  #     # this line allows the default_letter text added by this
  #     # method to be replaced by the value supplied by the API
  #     # e.g. http://demo.alaveteli.org/new/tgq?default_letter=this+is+a+test
  #     return @default_letter if @default_letter
  #     return nil if self.message_type == 'followup'
  #     "If you uncomment this line, this text will appear as default text in every message"
  #   end
  # end
end
